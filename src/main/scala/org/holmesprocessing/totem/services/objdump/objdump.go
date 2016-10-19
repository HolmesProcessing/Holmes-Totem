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
	"github.com/go-ini/ini"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"reflect"
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
	"os/exec"
	"regexp"
	"strconv"
)

// config structs
type Metadata struct {
	Name        string
	Version     string
	Description string
	Copyright   string
	License     string
}
type Settings struct {
	Port               string
	MaxNumberOfOpcodes string
}
type Config struct {
	Settings Settings
}

// global variables
var (
	config              Config // = &Config{}
	infoLogger          *log.Logger
	objdump_binary_path string
	opcodes_max         int64
	metadata            Metadata = Metadata{
		Name:        "Objdump",
		Version:     "1.2.0",
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

	// read metadata-files
	if data, err := ioutil.ReadFile(metadata.Description); err == nil {
		metadata.Description = strings.Replace(string(data), "\n", "<br>", -1)
	}
	if data, err := ioutil.ReadFile(metadata.License); err == nil {
		metadata.License = strings.Replace(string(data), "\n", "<br>", -1)
	}

	if configPath == "" {
		configPath, _ = filepath.Abs(filepath.Dir(os.Args[0]))
		configPath += "/service.conf"
	}

	config = load_config(configPath)
	opcodes_max, err = strconv.ParseInt(config.Settings.MaxNumberOfOpcodes, 10, 64)
	if err != nil {
		panic(err)
	}

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

	port := config.Settings.Port
	address := fmt.Sprintf(":%s", port)

	infoLogger.Printf("Binding to %s\n", address)
	infoLogger.Fatal(http.ListenAndServe(address, router))
}

// Parse a configuration file into a configuration structure.
func load_config(configPath string) Config {

	// Create a new config object. Initialize it empty for now.
	config := Config{Settings: Settings{}}

	// Prepare reflection to be able to set values later.
	r_settings := reflect.ValueOf(&(config.Settings)).Elem()

	// Attempt to read the INI-File. If it fails to open and read from the file,
	// throw a fatal error and exit.
	inifile, err := ini.Load(configPath)
	if err != nil {
		infoLogger.Fatalf("Unable to read config file %s", configPath)
	}

	// Get a list of all section names in the INI-File and iterate over them.
	// Convert each name to lower case and check if it corresponds to one of our
	// sections. If this is the case, set the respective mapping so we can find
	// this section within the INI-File again. (See loop over section_list)
	sections := make(map[string]string)
	for _, section_name := range inifile.SectionStrings() {
		lower_case := strings.ToLower(section_name)
		if lower_case == "metadata" || lower_case == "settings" {
			infoLogger.Printf("Found section %s (%s)\n", lower_case, section_name)
			sections[lower_case] = section_name
		}
	}

	// If one of our required sections isn't supplied, error out.
	if _, exists := sections["settings"]; !exists {
		infoLogger.Fatalln("Fatal Error: Unable to find a settings section in the supplied config")
	}

	// Iterate through the two sections and then over all relevant keys.
	// Using a lot of helper structures here, looks ugly, but effectively makes
	// this a bit more efficient and allows using the same code for all sections
	// and contained keys.
	type Mapping struct {
		key       string
		key_lower string
		exists    bool
		value     string
	}
	section_list := [2]string{"metadata", "settings"}
	ini_map := make(map[string]map[string]*Mapping)
	ini_keys := make(map[string][]string)
	ini_keys["settings"] = []string{"Port", "MaxNumberOfOpcodes"}

	for _, section_name := range section_list {
		// Per section we require a ini_map section, create it.
		// it consists of a Mapping struct reference containing information
		// about the setting parameter.
		ini_map[section_name] = make(map[string]*Mapping)
		for _, key := range ini_keys[section_name] {
			lower_case := strings.ToLower(key)
			// Since map entries are not addressable, we don't put in the struct
			// directly, but rather an address, making its values modifiable.
			ini_map[section_name][lower_case] = &Mapping{key: key, key_lower: lower_case}
		}
		// Grab the actual INI-File section to work with.
		section := inifile.Section(sections[section_name])
		// Go through all keys within this section.
		// We don't know which exact keys the setting values have (upper and
		// lower case may be mixed), as such we convert each key to lower case
		// and check if a respective mapping exists within the ini_map.
		// If that is the case, we define that the mapping is now "existing" and
		// fill in the value stored in the INI-File.
		// We only consider the LAST value of the respective key.
		for _, key := range section.KeyStrings() {
			lower_case := strings.ToLower(key)
			if mapping, exists := ini_map[section_name][lower_case]; exists {
				mapping.exists = true
				mapping.value = section.Key(key).String()
			}
		}
		// Once we're finished with the keys, go over all mappings of this
		// section.
		// If a mapping doesn't exist, throw a fatal error and exit.
		// If it exists however, use previously initialized reflection to set
		// the respective values in the config struct.
		// In case we are in the metadata section and if the key is description
		// or license load the file contents instead if the file is available.
		for _, mapping := range ini_map[section_name] {
			if !mapping.exists {
				infoLogger.Fatalf("Fatal Error: Missing key %s in the %s config\n", mapping.key, section_name)
			}
			r_settings.FieldByName(mapping.key).SetString(mapping.value)
		}
	}

	return config
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

func execute_objdump_error(w http.ResponseWriter, samplepath string, err error, stdout []byte) {
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
		strings.Replace(strings.TrimSpace(string(stdout)), "\n", "; ", -1),
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

	// Prepare helper variables and regular expressions.
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
	map_sections := make(map[string]*Section)
	opcodes := make([]string, opcodes_max)
	var (
		opcodes_total int64 = 0
		opcodes_index int64 = 0
		fileformat    string
		cur_section   *Section
		cur_block     *Block
		processed     bool
		expected      int
	)

	// Run objdump header dump mode
	// -w: wide output (not delimited to 80 chars)
	// -h: print headers
	objdump := exec.Command(objdump_binary_path, "-w", "-h", sample_path)
	stdout, err := objdump.Output()
	if err != nil {
		if err.Error() != "No Error" {
			execute_objdump_error(f_response, sample_path, err, stdout)
			return
		} else {
			// Again the ugly type switch, this time a bit more condensed as we only
			// expect *exec.ExitError to have the "No Error" value
			var i interface{}
			i = err
			switch i.(type) {
			case *exec.ExitError:
				// in this case it is no fatal error
				infoLogger.Println(string(err.(*exec.ExitError).Stderr))
			}
		}
	}

	// see next usage of lines_done for an explanation
	expected = expect_header_start
	lines := make(chan string, 0x100)
	lines_done := false
	go process_lines(stdout, lines, &lines_done)
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

	// Run objdump dissassemble mode
	// -w: wide output (not delimited to 80 chars)
	// -d: disassemble
	objdump = exec.Command(objdump_binary_path, "-w", "-d", sample_path)
	stdout, err = objdump.Output()
	if err != nil {
		if err.Error() != "No Error" {
			execute_objdump_error(f_response, sample_path, err, stdout)
			return
		} else {
			var i interface{}
			i = err
			switch i.(type) {
			case *exec.ExitError:
				// in this case it is no fatal error
				infoLogger.Println(string(err.(*exec.ExitError).Stderr))
			}
		}
	}

	// lines_done:
	//		this switch is necessary to let the lines processing goroutine
	// 		know that it has to stop, furthermore we need to empty the channel to
	//		avoid having a stuck lines processing goroutine (producer starvation)
	expected = expect_format
	lines = make(chan string, 0x100)
	lines_done = false
	go func() { process_lines(stdout, lines, &lines_done) }()
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
				http.Error(f_response, "Unable to determine file format", 500)
				infoLogger.Println("Fatal Error: Unable to determine file format.")
				return
			}
		}

		// Catch unprocessed error
		if !processed {
			http.Error(f_response, fmt.Sprintf("Unexpected output '%s'", line), 500)
			infoLogger.Printf("Fatal Error: Unable to process unexpected output '%s'. Expected='0x%s'.\n", line, strconv.FormatInt(int64(expected), 16))
			return
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

	// After all data is parsed, assemble json
	type AnalysisResult struct {
		Fileformat string              `json:"fileformat"`
		NoOpcodes  int64               `json:"number_of_opcodes"`
		Truncated  bool                `json:"truncated"`
		Sections   map[string]*Section `json:"sections"`
	}
	analysis_result := &AnalysisResult{}
	analysis_result.Fileformat = fileformat
	analysis_result.NoOpcodes = opcodes_total
	analysis_result.Truncated = truncated
	analysis_result.Sections = map_sections
	analysis_result_json, err := json.Marshal(analysis_result)

	f_response.Header().Set("Content-Type", "text/json; charset=utf-8")
	f_response.Write(analysis_result_json)

	elapsed_time := time.Since(start_time)
	infoLogger.Printf("Done, read a total of %d opcodes in %s.\n", opcodes_total, elapsed_time)
}

/**
* Helper function to get the next line from our output. Currently not working
* on the stdout pipe instead of the whole output. TODO: use stdout instead of
* complete output - might be more efficient (memory wise?)?.
 */
func process_lines(s []byte, out chan string, done *bool) {
	var (
		i    int
		a    int = 0
		size int = len(s)
	)
	for i = 0; i < size; i++ {
		if *done {
			break
		}
		if s[i] == '\n' {
			if i > a {
				out <- string(s[a:i])
			}
			a = i + 1
		}
	}
	if i > a && !*done {
		out <- string(s[a:i])
	}
	close(out)
}
