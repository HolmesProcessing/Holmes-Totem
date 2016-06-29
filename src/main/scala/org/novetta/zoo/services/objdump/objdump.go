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
    "os"
    "path/filepath"
    "log"
    "flag"
    "github.com/go-ini/ini"
    "io/ioutil"
    "strings"
    "fmt"
    "reflect"
)

/*
 * Imports for serving on a socket and handling routing of incoming request.
 */
import (
    "net/http"
    "github.com/julienschmidt/httprouter"
    "encoding/json"
)

/*
 * Imports for request execution.
 */
import (
    "os/exec"
    "regexp"
    "strconv"
)


// declare json structs
type JSONResult struct {
    Offsets         []int
    Instructions    []string
}

// config structs
type Metadata struct {
    Name                string
    Version             string
    Description         string
    Copyright           string
    License             string
}
type Settings struct {
    Port                string
    InfoURL             string
    AnalysisURL         string
    MaxNumberOfOpcodes  string
}
type Config struct {
    metadata Metadata
    settings Settings
}

// global variables
var (
    config                  Config  // = &Config{}
    info                    *log.Logger
    objdump_binary_path     string
)


// main logic
func main () {
    var (
        // err error
        configPath string
    )
    
    // setup logging
    info = log.New(os.Stdout, "", log.Ltime|log.Lshortfile)
    
    // load config
    flag.StringVar(&configPath, "config", "", "Path to the configuration file")
    flag.Parse()
    
    if configPath == "" {
        configPath, _ = filepath.Abs(filepath.Dir(os.Args[0]))
        configPath += "/service.conf"
    }
    
    config = load_config(configPath)
    
    // find objdump binary path
    if binary, err := exec.LookPath("objdump"); err != nil {
        log.Fatalln("Unable to locate objdump binary, is objdump installed?", err)
    } else {
        objdump_binary_path = binary
    }
    
    // setup http handlers
    router := httprouter.New()
    router.GET("/objdump/:file", handler_analyze)
    router.GET("/", handler_info)
    
    port := config.settings.Port
    address := fmt.Sprintf(":%s",port)
    
    log.Printf("Binding to %s\n", address)
    log.Fatal(http.ListenAndServe(address, router))
}


// Parse a configuration file into a configuration structure.
func load_config (configPath string) Config {
    
    // Create a new config object. Initialize it empty for now.
    config := Config{metadata: Metadata{}, settings: Settings{}}
    
    // Prepare reflection to be able to set values later.
    r_metadata := reflect.ValueOf(&(config.metadata)).Elem()
    r_settings := reflect.ValueOf(&(config.settings)).Elem()
    
    // Attempt to read the INI-File. If it fails to open and read from the file,
    // throw a fatal error and exit.
    inifile, err := ini.Load(configPath)
    if err != nil {
        log.Fatalf("Unable to read config file %s", configPath)
    } else {
        log.Printf("Reading config file %s\n", configPath)
    }
    
    // Get a list of all section names in the INI-File and iterate over them.
    // Convert each name to lower case and check if it corresponds to one of our
    // sections. If this is the case, set the respective mapping so we can find
    // this section within the INI-File again. (See loop over section_list)
    sections := make(map[string]string)
    for _, section_name := range inifile.SectionStrings() {
        lower_case := strings.ToLower(section_name)
        if lower_case == "metadata" || lower_case == "settings" {
            log.Printf("Found section %s (%s)\n", lower_case, section_name)
            sections[lower_case] = section_name
        }
    }
    
    // If one of our required sections isn't supplied, error out.
    if _, exists := sections["metadata"]; !exists {
        log.Fatalln("Fatal Error: Unable to find a metadata section in the supplied config")
    }
    if _, exists := sections["settings"]; !exists {
        log.Fatalln("Fatal Error: Unable to find a settings section in the supplied config")
    }
    
    // Iterate through the two sections and then over all relevant keys.
    // Using a lot of helper structures here, looks ugly, but effectively makes
    // this a bit more efficient and allows using the same code for all sections
    // and contained keys.
    type Mapping struct {
        key string
        key_lower string
        exists bool
        value string
    }
    section_list  := [2]string{"metadata", "settings"}
    ini_map   := make(map[string]map[string]*Mapping)
    ini_keys  := make(map[string][]string)
    ini_keys["metadata"] = []string{"Name", "Version", "Description", "Copyright", "License"}
    ini_keys["settings"] = []string{"Port", "InfoURL", "AnalysisURL", "MaxNumberOfOpcodes"}
    
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
                mapping.value  = section.Key(key).String()
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
                log.Fatalf("Fatal Error: Missing key %s in the %s config\n", mapping.key, section_name)
            }
            if section_name == "metadata" {
                if mapping.key_lower == "description" || mapping.key_lower == "license" {
                    if data, err := ioutil.ReadFile(mapping.value); err == nil {
                        mapping.value = strings.Replace(string(data), "\n", "<br>", -1)
                    }
                }
                r_metadata.FieldByName(mapping.key).SetString(mapping.value)
            } else {
                r_settings.FieldByName(mapping.key).SetString(mapping.value)
            }
        }
    }
    
    return config
}


func handler_info (f_response http.ResponseWriter, r *http.Request, ps httprouter.Params) {
    result := fmt.Sprintf(`
        <p>%s - %s</p>
        <hr>
        <p>%s</p>
        <hr>
        <p>%s</p>
        `,
        config.metadata.Name,
        config.metadata.Version,
        config.metadata.Description,
        config.metadata.License)
    fmt.Fprint(f_response, result)
}


func handler_analyze (f_response http.ResponseWriter, request *http.Request, params httprouter.Params) {
    log.Println("Serving request:", request)
    start_time := time.Now()
    
    sample_path := "/tmp/" + params.ByName("file")
    if _, err := os.Stat(sample_path); os.IsNotExist(err) {
        http.NotFound(f_response, request)
        log.Printf("Error accessing sample (file: %s):", sample_path)
        log.Println(err)
        return
    }
    
    // Run objdump
    // -d: disassemble
    // -w: wide output (not delimited to 80 chars)
    objdump     := exec.Command(objdump_binary_path, "-w", "-d", sample_path)
    stdout, err := objdump.Output()
    
    if err != nil {
        http.Error(f_response, "Executing objdump failed", 500)
        log.Printf("Error executing objdump (file: %s):", sample_path)
        log.Println(err)
        return
    }
    
    // Prepare helper variables and regular expressions.
    // Allocate one big opcode array, for blocks only save slices - way more
    // efficient, no copy actions.
    // Another efficiency messure is to have expected values, trimming down on
    // regex comparisons.
    // If a type is not expected, it is not tested for and the most likely type
    // is tested first. Opcodes are the most likely, followed by block, followed
    // by section. The file format should only be specified once and it must be
    // first.
    // Unexpected output is deemed an error and results in an exit.
    // By using this expectance feature, we potentially reduce the amount of
    // regular expressions executed to a minimum.
    type Block struct {
        Name        string      `json:"name"`
        Offset      string      `json:"offset"`
        Start_index int64       `json:"-"`
        Opcodes     []string    `json:"opcodes"`
    }
    type Section struct {
        Name    string          `json:"name"`
        // offset  string          `json:"offset"`
        Blocks  []*Block        `json:"blocks"`
    }
    map_sections := make(map[string]*Section)
    
    var (
        line            string
        line_offset     int
        line_more       bool
        opcodes_max     int64
        opcodes_total   int64
        opcodes_index   int64
        fileformat      string
        cur_section     *Section
        cur_block       *Block
        processed       bool
    )
    
    opcodes_max, _   = strconv.ParseInt(config.settings.MaxNumberOfOpcodes, 10, 64)
    opcodes         := make([]string, opcodes_max)
    
    expect_format   := 0x1
    expect_section  := 0x2
    expect_block    := 0x4
    expect_opcode   := 0x8
    expected        := expect_format
    
    re_fileformat   := regexp.MustCompile("file format ([^ ]*)") // 1 format
    re_section      := regexp.MustCompile("^Disassembly of section ([^ :]*)") // 1 name
    re_block        := regexp.MustCompile("^0*([0-9a-f]+)( <([^>]+)>)?:") // 1 off, 3 name
    // the opcode params are not of any interest right now
    // re_opcode       := regexp.MustCompile("^  0*([0-9a-f]+):\\t[^\\t]+\\t(.*)") // 1 off, 2 op
    re_opcode       := regexp.MustCompile("^  0*([0-9a-f]+):\\t[^\\t]+\\t([^ ]*)") // 1 off, 2 op
    
    opcodes_total = 0
    opcodes_index = 0
    
    line, line_offset, line_more = nextline(stdout, 0)
    for line_more {
        
        // fmt.Fprint(f_response, line+"\n")
        
        processed = false
        
        // This is the most likely case, as there should be much more opcodes
        // than blocks or sections. As such this should be checked for first.
        if (expected & expect_opcode) != 0 {
            if result := re_opcode.FindStringSubmatch(line); len(result)>0 {
                opcodes[opcodes_total] = result[2]
                // Assigning a slice is as fast as it can possibly get, this
                // just saves a start and an end pointer.
                cur_block.Opcodes = opcodes[cur_block.Start_index:opcodes_total+1]
                opcodes_total += 1
                if opcodes_total >= opcodes_max {
                    // we reached our max opcodes!
                    line, line_offset, line_more = nextline(stdout, line_offset)
                    break
                }
                expected = expect_section | expect_block | expect_opcode
                processed = true
            }
        }
        
        // The second most likely occurence is that we have a block (each
        // section may have multiple blocks).
        if !processed && (expected & expect_block) != 0 {
            if result := re_block.FindStringSubmatch(line); len(result)>0 {
                // Create a new section block, depending on whether we can
                // detect a name, we create a named block or not.
                if len(result)>=4 {
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
        if !processed && (expected & expect_section) != 0 {
            if result := re_section.FindStringSubmatch(line); len(result)>0 {
                if _, exists := map_sections[result[1]]; exists {
                    log.Printf("Error: Found duplicate section %s, ignoring.\n", result[1])
                } else {
                    cur_section = &Section{Name: result[1]}
                    map_sections[result[1]] = cur_section
                }
                expected = expect_block
                processed = true
            }
        }
        
        // This should only happen once and only at the start of the input.
        // As such this comparison is last.
        if !processed && (expected & expect_format) != 0 {
            if result := re_fileformat.FindStringSubmatch(line); len(result)>0 {
                log.Printf("Found file format specifier %s\n", result[1])
                fileformat = result[1]
                expected = expect_section
                processed = true
            } else {
                log.Fatalln("Fatal Error: Unable to determine file format.")
            }
        }
        
        // Catch unprocessed error
        if !processed {
            log.Fatalf("Fatal Error: Unable to process unexpected output '%s', expected=%x.\n", line, expected)
        }
        
        // Get the next line.
        line, line_offset, line_more = nextline(stdout, line_offset)
    }
    
    // check if we have truncated the output
    truncated := false
    if opcodes_total >= opcodes_max && line_more {
        truncated = true
    }
    
    // After all data is parsed, assemble json
    type AnalysisResult struct {
        Fileformat string               `json:"fileformat"`
        NoOpcodes  int64                `json:"number_of_opcodes"`
        Truncated  bool                 `json:"truncated"`
        Sections   map[string]*Section  `json:"sections"`
    }
    analysis_result := &AnalysisResult{}
    analysis_result.Fileformat = fileformat
    analysis_result.NoOpcodes  = opcodes_total
    analysis_result.Truncated  = truncated
    analysis_result.Sections   = map_sections
    analysis_result_json, err := json.Marshal(analysis_result)
    
    // fmt.Println(string(analysis_result_json))
    f_response.Header().Set("Content-Type","text/json; charset=utf-8")
    fmt.Fprint(f_response, string(analysis_result_json))
    
    elapsed_time := time.Since(start_time)
    log.Printf("Done, read a total of %d opcodes in %s.\n", opcodes_total, elapsed_time)
}


/**
* Helper function to get the next line from our output. Currently not working
* on the stdout pipe instead of the whole output. TODO: use stdout instead of
* complete output - might be more efficient (memory wise?)?.
*/
var nextline_buffer [0x1000]byte
func nextline (s []byte, offset int) (string, int, bool) {
    var (
        i int
        b byte
        size int
    )
    
    i = 0
    size = len(s)
    
    for i < 0x1000 && offset+i < size {
        b = s[offset+i]
        
        nextline_buffer[i] = b
        i = i+1
        
        if b == '\n' {
            // ignore empty lines
            if i==1 {
                offset += i
                i = 0
                continue
            }
            break
        }
    }
    
    interims := nextline_buffer[0:i]
    if interims[i-1] == '\n' {
        interims = interims[0:i-1]
    }
    
    result := string(interims)
    
    if offset+i < size {
        return result, offset+i, true
    } else {
        return result, offset+i, false
    }
}
