package main

/*
 * Imports for messuring execution time of requests
 */
import (
	"time"
)

/*
 * Imports for reading the config, logging and command line argument parsing.
 */
import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
)

/*
 * Imports for serving on a socket and handling routing of incoming request.
 */
import (
	"encoding/json"
	"github.com/julienschmidt/httprouter"
	"net/http"
)

/*
 * Imports for request execution.
 */
import (
	"errors"
	"io"
	"os/exec"
	"regexp"
	"runtime/debug"
	"strconv"
)

type Metadata struct {
	Name        string
	Version     string
	Description string
	Copyright   string
	License     string
}

// config structs
type Setting struct {
	HTTPBinding string `json:"HTTPBinding"`
}

type OBJDUMP struct {
	MaxNumberOfOpcodes int `json:"MaxNumberOfOpcodes"`
}

type Config struct {
	Settings Setting `json:"settings"`
	Objdump  OBJDUMP `json:"objdump"`
}

// global variables
var (
	config              Config // = &Config{}
	infoLogger          *log.Logger
	objdump_binary_path string
	opcodes_max         int64
	metadata            Metadata = Metadata{
		Name:        "Objdump",
		Version:     "1.2.2",
		Description: "./README.md",
		Copyright:   "Copyright 2016 Holmes Group LLC",
		License:     "./LICENSE",
	}
)

// main logic
func main() {
	var (
		err        error
		configPath string
	)

	// setup logging
	infoLogger = log.New(os.Stdout, "", log.Ltime|log.Lshortfile)

	// load config
	flag.StringVar(&configPath, "config", "", "Path to the configuration file")
	flag.Parse()

	config, err := load_config(configPath)
	if err != nil {
		panic(err)
	}

	//opcodes_max := config.Logic.MaxNumberOfOpcodes

	// find objdump binary path
	if binary, err := exec.LookPath("objdump"); err != nil {
		infoLogger.Fatalln("Unable to locate objdump binary, is objdump installed?", err)
	} else {
		objdump_binary_path = binary
	}

	// setup http handlers
	router := httprouter.New()
	router.GET("/analyze/", handler_analyze)
	router.GET("/", handler_info)

	infoLogger.Printf("Binding to %s\n", config.Settings.HTTPBinding)
	infoLogger.Fatal(http.ListenAndServe(config.Settings.HTTPBinding, router))
}

// Parse a configuration file into a configuration structure.
func load_config(configPath string) (*Config, error) {
	config := &Config{}

	// if no path is supplied look in the current dir
	if configPath == "" {
		configPath, _ = filepath.Abs(filepath.Dir(os.Args[0]))
		configPath += "/service.conf"
	}

	cfile, _ := os.Open(configPath)
	if err := json.NewDecoder(cfile).Decode(&config); err != nil {
		return config, err
	}

	if metadata.Description != "" {
		if data, err := ioutil.ReadFile(string(metadata.Description)); err == nil {
			metadata.Description = strings.Replace(string(data), "\n", "<br>", -1)
		}
	}

	if metadata.License != "" {
		if data, err := ioutil.ReadFile(string(metadata.License)); err == nil {
			metadata.License = strings.Replace(string(data), "\n", "<br>", -1)
		}
	}

	return config, nil
}

func handler_info(f_response http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	fmt.Fprintf(f_response, `<p>%s - %s</p>
        <hr>
        <p>%s</p>
        <hr>
        <p>%s</p>
        `,
		metadata.Name,
		metadata.Version,
		metadata.Description,
		metadata.License)
}

// Result structures.
// Each result contains all sections that a file contains, but blocks are only
// listed as long as the opcode limit is not reached.
type Block struct {
	Name        string   `json:"name"`
	Offset      string   `json:"offset"`
	Start_index int64    `json:"-"`
	Opcodes     []string `json:"opcodes"`
	Truncated   bool     `json:"truncated"`
}
type Section struct {
	Name      string   `json:"name"`
	Flags     []string `json:"flags"`
	Blocks    []*Block `json:"blocks"`
	Truncated bool     `json:"truncated"`
	// TODO: add offset maybe?
	// offset  string          `json:"offset"`
	// Internal settings
	initialized bool
}

type AnalysisResult struct {
	Fileformat string              `json:"fileformat"`
	NoOpcodes  int64               `json:"number_of_opcodes"`
	Truncated  bool                `json:"truncated"`
	Sections   map[string]*Section `json:"sections"`
}

// Initialize all constants for parsing.
// - Expectancy constants (binary flags)
// - Regular expressions
var (
	expect_header_start int = 0x10
	expect_header_entry int = 0x20

	expect_format  int = 0x1
	expect_section int = 0x2
	expect_block   int = 0x4
	expect_opcode  int = 0x8

	// 1 index, 2 name, 3 flags (comma separated)
	re_header_table_start = regexp.MustCompile("^Idx +Name +Size +VMA +LMA +File +off +Algn +Flags")
	re_header_table_entry = regexp.MustCompile("^ *([0-9]+) +([^ ]+) +[0-9a-f]+ +[0-9a-f]+ +[0-9a-f]+ +[0-9a-f]+ +[^ ]+ +(.*)")

	re_fileformat = regexp.MustCompile("file format ([^ ]*)")              // 1 format
	re_section    = regexp.MustCompile("^Disassembly of section ([^ :]*)") // 1 name
	re_block      = regexp.MustCompile("^0*([0-9a-f]+)( <([^>]*)>)?:")     // 1 off, 3 name
	// the opcode params are not of any interest right now, as such this is sufficient:
	re_opcode   = regexp.MustCompile("^ *0*([0-9a-f]+):\\t[^\\t]+\\t([^ ]*)") // 1 off, 2 op
	re_ellipsis = regexp.MustCompile("^[ \\t]+\\.\\.\\.$")
)

func check_objdump_error(w http.ResponseWriter, sample_path string, err error) bool {
	if err != nil {
		if err.Error() != "No Error" {
			execute_objdump_error(w, sample_path, err)
		} else {
			// Again the ugly type switch, this time a bit more condensed as we only
			// expect *exec.ExitError to have the "No Error" value
			if exitErr, ok := err.(*exec.ExitError); ok {
				// in this case it is no fatal error
				infoLogger.Println(string(exitErr.Stderr))
				return false
			}
			// otherwise however it is
			execute_objdump_error(w, sample_path, err)
		}
		return true
	}
	return false
}

func execute_objdump_error(w http.ResponseWriter, samplepath string, err error) {
	http.Error(w, "Executing objdump failed", 500)
	// This ugly type switch fixes the panic that occured when it wasn't the
	// expected *exec.ExitError
	var (
		iface       interface{}
		detailedErr string = ""
	)
	iface = err
	switch iface.(type) {
	case *exec.ExitError:
		detailedErr = string(err.(*exec.ExitError).Stderr)
	case *os.PathError:
		err := err.(*os.PathError)
		detailedErr = err.Path + " - " + err.Op + " - " + err.Err.Error()
	}
	infoLogger.Printf("Error executing objdump (file: %s): %s %s %s",
		samplepath,
		err.Error(),
		strings.Replace(strings.TrimSpace(detailedErr), "\n", "; ", -1),
	)
}

func handler_analyze(f_response http.ResponseWriter, request *http.Request, params httprouter.Params) {
	infoLogger.Println("Serving request:", request.RequestURI)
	start_time := time.Now()

	obj := request.URL.Query().Get("obj")
	if obj == "" {
		http.Error(f_response, "Missing argument 'obj'", 400)
		return
	}
	sample_path := "/tmp/" + obj
	if _, err := os.Stat(sample_path); os.IsNotExist(err) {
		http.NotFound(f_response, request)
		infoLogger.Printf("Error accessing sample (file: %s):", sample_path)
		infoLogger.Println(err)
		return
	}

	// analyze headers
	map_sections, err := analyze_headers(sample_path)
	if check_objdump_error(f_response, sample_path, err) {
		return
	}

	// analyze disassembly
	analysis_result, err, err2 := analyze_disassembly(sample_path, map_sections)
	if check_objdump_error(f_response, sample_path, err) {
		return
	}
	if err2 != nil {
		http.Error(f_response, err2.Error(), 500)
		return
	}

	// marshal to json and send to client
	analysis_result_json, err := json.Marshal(analysis_result)
	if err != nil {
		infoLogger.Println("Error creating json:", err)
		return
	}
	f_response.Header().Set("Content-Type", "text/json; charset=utf-8")
	f_response.Write(analysis_result_json)

	// for the record the time measure
	elapsed_time := time.Since(start_time)
	infoLogger.Printf("Done, read a total of %d opcodes in %s.\n", analysis_result.NoOpcodes, elapsed_time)

	// attempt to clean as much memory as possible
	// infoLogger.Println("Cleaning memory")
	// start_time = time.Now()
	debug.FreeOSMemory()
	// elapsed_time = time.Since(start_time)
	// infoLogger.Printf("Done cleaning memory in %s.\n", elapsed_time)
}

/**
* Helper function to analyze stdout from objdump
 */
func analyze_headers(sample_path string) (map[string]*Section, error) {
	var (
		map_sections     = make(map[string]*Section)
		lines            = make(chan string, 0x100)
		lines_done       = false
		expected     int = expect_header_start
		stdout       io.ReadCloser
		err          error
	)
	// Run objdump in header dump mode
	// -w: wide output (not delimited to 80 chars)
	// -h: print headers
	objdump := exec.Command(objdump_binary_path, "-w", "-h", sample_path)
	if stdout, err = objdump.StdoutPipe(); err == nil {
		defer stdout.Close()
		if err = objdump.Start(); err == nil {
			// subroutine to handle line splitting
			go process_lines(stdout, lines, &lines_done)
			// handle incoming lines
			for line := range lines {
				if expected == expect_header_start {
					if result := re_header_table_start.FindStringSubmatch(line); len(result) > 0 {
						expected = expect_header_entry
					}
				} else {
					if result := re_header_table_entry.FindStringSubmatch(line); len(result) > 0 {
						flags := strings.Split(result[3], ", ")
						map_sections[result[2]] = &Section{
							Name:  result[2],
							Flags: flags,
						}
					}
				}
			}
			// wait for objdump to finish if it hasn't already
			err = objdump.Wait()
		}
	}
	return map_sections, err
}

/**
* Helper function to analyze stdout from objdump
* First error returned is the objdump error, second can be an internal error
 */
func analyze_disassembly(sample_path string, map_sections map[string]*Section) (*AnalysisResult, error, error) {
	// Prepare helper variables.
	// Allocate one big opcode array, for blocks only save slices - way more
	// efficient, no copy actions.
	// Another efficiency measure is to have expected values, reducing the number
	// of regular expressions executed.
	// If a type is not expected, it is not tested for and the most likely type
	// is tested first. Opcodes are the most likely, followed by block, followed
	// by section. The file format should only be specified once and it must be
	// first.
	// Unexpected output is deemed an error and results in an exit.
	// By using this expectance feature, we potentially reduce the amount of
	// regular expressions executed to a minimum.
	opcodes := make([]string, opcodes_max)
	var (
		opcodes_total   int64 = 0
		opcodes_index   int64 = 0
		fileformat      string
		cur_section     *Section
		cur_block       *Block
		processed       bool
		expected        int = expect_format
		err             error
		stdout          io.ReadCloser
		lines           = make(chan string, 0x100)
		lines_done      = false
		analysis_result = &AnalysisResult{}
	)

	// Run objdump dissassemble mode
	// -w: wide output (not delimited to 80 chars)
	// -d: disassemble
	objdump := exec.Command(objdump_binary_path, "-w", "-d", sample_path)
	if stdout, err = objdump.StdoutPipe(); err == nil {
		defer stdout.Close()
		if err = objdump.Start(); err == nil {
			// subroutine to handle line splitting
			go process_lines(stdout, lines, &lines_done)
			// handle incoming lines
			for line := range lines {
				// Indicator if the line was processed.
				processed = false
				// This is the most likely case, as there should be much more opcodes
				// than blocks or sections. As such this should be checked for first.
				if (expected & expect_opcode) != 0 {
					if result := re_opcode.FindStringSubmatch(line); len(result) > 0 {
						// TODO: continue to go on if limit is reached, but not record, only record
						// missed sections
						if opcodes_total < opcodes_max {
							opcodes[opcodes_total] = result[2]
							// Assigning a slice is as fast as it can possibly get, this
							// just saves a start and an end pointer.
							cur_block.Opcodes = opcodes[cur_block.Start_index : opcodes_total+1]
						} else {
							// We are finished with parsing, we reached our limit for opcodes.
							cur_block.Truncated = true
							cur_section.Truncated = true
							// empty remaining lines, set lines_done switch to true, both together
							// ensures termination of the process lines goroutine
							lines_done = true
							for range lines {
							}
							break
						}
						opcodes_total += 1
						// Do not break upon reaching max opcode count anymore, we want those
						// other section names and a note that we truncated:
						// if opcodes_total >= opcodes_max {
						// 	// we reached our max opcodes!
						// 	line, line_offset, line_more = nextline(stdout, line_offset, line_buffer)
						// 	break
						// }
						expected = expect_section | expect_block | expect_opcode
						processed = true
					}
				}
				// Tackle ellipsis (consecutive nullbytes).
				if !processed && (expected&expect_opcode) != 0 {
					if result := re_ellipsis.FindStringSubmatch(line); len(result) > 0 {
						processed = true
					}
				}
				// The second most likely occurence is that we have a block (each
				// section may have multiple blocks).
				if !processed && (expected&expect_block) != 0 {
					if result := re_block.FindStringSubmatch(line); len(result) > 0 {
						// Create a new section block, depending on whether we can
						// detect a name, we create a named block or not.
						if len(result) >= 4 {
							cur_block = &Block{Name: result[3], Offset: result[1]}
						} else {
							cur_block = &Block{Name: "unknown", Offset: result[1]}
						}
						cur_block.Offset = result[1]
						opcodes_index = opcodes_total
						cur_block.Start_index = opcodes_index
						// Make sure to update the section.
						cur_section.Blocks = append(cur_section.Blocks, cur_block)
						// To be as open as possible, enable section, block and opcode
						// as next expected. Theoretically it should be only opcode ...
						expected = expect_opcode
						processed = true
					}
				}
				// Then we have the sections, which we should have a couple in each
				// binary. Next to the file format this is the least likely to be hit.
				// Whilst there is only one file format there may be quite a bunch of
				// sections.
				if !processed && (expected&expect_section) != 0 {
					if result := re_section.FindStringSubmatch(line); len(result) > 0 {
						if section, exists := map_sections[result[1]]; exists && section.initialized {
							infoLogger.Printf("Error: Found duplicate section %s, ignoring.\n", result[1])
						} else if exists {
							cur_section = section
							cur_section.initialized = true
						} else {
							// TODO: should this be a fatal error?
							infoLogger.Println("Error: Found a section that was not described in the header: " + result[1])
						}
						expected = expect_block
						processed = true
					}
				}
				// This should only happen once and only at the start of the input.
				// As such this comparison is last.
				if !processed && (expected&expect_format) != 0 {
					if result := re_fileformat.FindStringSubmatch(line); len(result) > 0 {
						fileformat = result[1]
						expected = expect_section
						processed = true
					} else {
						infoLogger.Println("Fatal Error: Unable to determine file format.")
						return nil, nil, errors.New("Unable to determine file format")
					}
				}
				// Catch unprocessed error
				if !processed {
					infoLogger.Printf("Fatal Error: Unable to process unexpected output '%s'. Expected='0x%s'.\n", line, strconv.FormatInt(int64(expected), 16))
					return nil, nil, errors.New(fmt.Sprintf("Unexpected output '%s'", line))
				}
			}
			// check if we have truncated the output
			// if there is no current section avoid null pointer dereference
			var truncated bool
			if cur_section == nil {
				truncated = true
			} else {
				truncated = cur_section.Truncated
				if line, more := <-lines; line != "" || more {
					truncated = true
				}
			}
			analysis_result.Fileformat = fileformat
			analysis_result.NoOpcodes = opcodes_total
			analysis_result.Truncated = truncated
			analysis_result.Sections = map_sections
			// wait for objdump to finish if it hasn't already
			err = objdump.Wait()
		}
	}
	return analysis_result, err, nil
}

/**
* Helper function to get the next line from our output. Currently not working
* on the stdout pipe instead of the whole output. TODO: use stdout instead of
* complete output - might be more efficient (memory wise?)?.
 */
func process_lines(stdout io.ReadCloser, out chan string, done *bool) {
	defer close(out)
	// Param: done
	//		this switch is necessary to let the lines processing goroutine
	// 		know that it has to stop, furthermore we need to empty the channel to
	//		avoid having a stuck lines processing goroutine (producer starvation)
	var (
		i    int
		a    int
		s    []byte = make([]byte, 0x1000)
		lbuf []byte = make([]byte, 0)
		nbuf []byte
		size int
		err  error
	)
	for true {
		size, err = stdout.Read(s)
		if err != nil {
			break
		}
		a = 0
		for i = 0; i < size && !*done; i++ {
			if s[i] == '\n' {
				if i > a || len(lbuf) > 0 { // skip empty lines (e.g. a=0, i=0), but then flush a non-empty lbuf
					if len(lbuf) > 0 {
						out <- string(lbuf) + string(s[a:i])
						lbuf = make([]byte, 0)
					} else {
						out <- string(s[a:i])
					}
				}
				a = i + 1
			}
		}
		// append remaining unprocessed output to lbuf
		if i > a && !*done {
			nbuf = make([]byte, len(lbuf)+i-a)
			copy(nbuf, lbuf)
			copy(nbuf[len(lbuf):], s[a:i])
			lbuf = nbuf
		}
	}
	// process remaining output
	if len(lbuf) > 0 && !*done {
		out <- string(lbuf)
	}
	// check error sequence (EOF is expected, anything else is unexpected)
	if err != nil {
		if err != io.EOF {
			infoLogger.Println("Error splitting lines:", err)
		}
	}
}
