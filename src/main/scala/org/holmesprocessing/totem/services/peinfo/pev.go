package main

// #include<libpe/pe.h>
// #cgo LDFLAGS: -lpe
import "C"
import (
	//Imports for measuring execution time of requests
	"time"

	//Imports for reading the config, logging and command line argument parsing.
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	_ "strconv"
	"strings"

	//Imports for serving on a socket and handling routing of incoming request.
	"encoding/json"
	"github.com/julienschmidt/httprouter"
	"net/http"

	// Import to reduce service memory footprint
	"runtime/debug"
)

type Result struct {
	Optional          OptionalHeaders `json:"Optional"`
	Dos               DosHeaders      `json:"DosHeaders"`
	Coff              CoffHeaders     `json:"CoffHeaders"`
	Directories       Directory       `json:"directories"`
	Directories_count int             `json:"directories_count"`
	Sections          Section         `json:"sections"`
	Sections_count    int             `json:"sectionscount"`
}

type OptionalHeaders struct {
	Magic                       int `json:"Magic"`
	MajorLinkerVersion          int `json:"MajorLinkerVersion"`
	MinorLinkerVersion          int `json:"MinorLinkerVersion"`
	SizeOfCode                  int `json:"SizeOfCode"`
	SizeOfInitializedData       int `json:"SizeOfUninitializedData"`
	SizeOfUninitializedData     int `json:"SizeOfUninitializedData"`
	AddressOfEntryPoint         int `json:"AddressOfEntryPoint"`
	BaseOfCode                  int `json:"BaseOfCode"`
	ImageBase                   int `json:"ImageBase"`
	SectionAlignment            int `json:"SectionAlignment"`
	FileAlignment               int `json:"FileAlignment"`
	MajorOperatingSystemVersion int `json:"MajorOperatingSystemVersion"`
	MinorOperatingSystemVersion int `json:"MinorOperatingSystemVersion"`
	MajorImageVersion           int `json:"MajorImageVersion"`
	MinorImageVersion           int `json:"MinorImageVersion"`
	MajorSubsystemVersion       int `json:"MajorSubsystemVersion"`
	MinorSubsystemVersion       int `json:"MinorSubsystemVersion"`
	Reserved1                   int `json:Reserved1"`
	SizeOfImage                 int `json:"SizeOfImage"`
	SizeOfHeaders               int `json:"SizeOfHeaders"`
	CheckSum                    int `json:"CheckSum"`
	Subsystem                   int `json:"Subsystem"`
	DllCharacteristics          int `json:"DllCharacteristics"`
	SizeOfStackReserve          int `json:"SizeOfStackReserve"`
	SizeOfStackCommit           int `json:"SizeOfStackCommit"`
	SizeOfHeapReserve           int `json:"SizeOfHeapReserve"`
	SizeOfHeapCommit            int `json:"SizeOfHeapCommit"`
	LoaderFlags                 int `json:"LoaderFlags"`
	NumberOfRvaAndSizes         int `json:"NumberOfRvaAndSizes"`
}

type DosHeaders struct {
	Magic    int `json:"e_magic"` // Magic Number
	Cblp     int `json:"e_cblp"`  //
	Cp       int `json:"e_cblp"`
	Crlc     int `json:"e_crlc"`
	Cparhdr  int `json:"e_cparhdr"`
	Minalloc int `json:"e_minalloc"`
	Maxalloc int `json:"e_maxalloc"`
	Ss       int `json:"e_ss"`
	Sp       int `json:"e_sp"`
	Csum     int `json:"e_csum"`
	Ip       int `json:"e_ip"`
	Cs       int `json:"e_cs"`
	Lfarlc   int `json:"e_lfarlc"`
	Ovno     int `json:"e_ovno"`
	Res      int `json:"e_res"`
	Oemid    int `json:"e_oemid"`
	Oeminfo  int `json:"e_oeminfo"`
	Res2     int `json:"e_res2"`
	Lfanew   int `json:"e_lfanew"`
}

type CoffHeaders struct {
	Machine              int `json:"Machine"`
	NumberOfSections     int `json:"NumberOfSections"`
	TimeDateStamp        int `json:"TimeDateStamp"`
	PointerToSymbolTable int `json:"TimeDateStamp"`
	NumberOfSymbols      int `json:"NumberOfSymbols"`
	SizeOfOptionalHeader int `json:"SizeOfOptionalHeader"`
	Characteristics      int `json:"Characteristics"`
}

type Directory struct {
	VirtualAddress int `json:"VirtualAddress"`
	Size           int `json:"Size"`
}

type Section struct {
	VirtualAddress       int `json:"VirtualAddress"`
	PointerToRawData     int `json:"PointerToRawData"`
	PointerToRelocations int `json:"PointerToRelocations"` // always zero in executables
	PointerToLinenumbers int `json:"PointerToLinenumbers"` //deprecated
	NumberOfRelocations  int `json:"NumberOfRelocations"`
	NumberOfLinenumbers  int `json:"NumberOfLinenumbers"` //deprecated
	Characteristics      int `json:"Characteristics"`
}

// config structs
type Metadata struct {
	Name        string
	Version     string
	Description string
	Copyright   string
	License     string
}

type Config struct {
	HTTPBinding string
}

var (
	config   *Config
	info     *log.Logger
	metadata Metadata = Metadata{
		Name:        "PEinfo",
		Version:     "1.0.0",
		Description: "./README.md",
		Copyright:   "Copyright 2017 Holmes Group LLC",
		License:     "./LICENSE",
	}
)

func main() {
	var (
		err        error
		configPath string
	)

	// setup logging
	info = log.New(os.Stdout, "", log.Ltime|log.Lshortfile)

	// load config
	flag.StringVar(&configPath, "config", "", "Path to the configuration file")
	flag.Parse()

	config, err = load_config(configPath)
	if err != nil {
		log.Fatalln("Couldn't decode config file without errors!", err.Error())
	}

	// setup http handlers
	router := httprouter.New()
	router.GET("/analyze/", handler_analyze)
	router.GET("/", handler_info)

	info.Printf("Binding to %s\n", config.HTTPBinding)
	log.Fatal(http.ListenAndServe(config.HTTPBinding, router))
}

// Parse a configuration file into a Config structure.

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

func handler_analyze(f_response http.ResponseWriter, request *http.Request, params httprouter.Params) {
	// ms-xy: calling FreeOSMemory manually drastically reduces the memory
	// footprint at the cost of a little bit of cpu efficiency (due to gc runs
	// after every call to handler_analyze)
	defer debug.FreeOSMemory()

	info.Println("Serving request:", request)
	start_time := time.Now()

	obj := request.URL.Query().Get("obj")
	if obj == "" {
		http.Error(f_response, "Missing argument 'obj'", 400)
		return
	}
	sample_path := "/tmp/" + obj
	if _, err := os.Stat(sample_path); os.IsNotExist(err) {
		http.NotFound(f_response, request)
		info.Printf("Error accessing sample (file: %s):", sample_path)
		info.Println(err)
		return
	}

	var err C.pe_err_e
	var ctx C.pe_ctx_t
	cstr := C.CString(sample_path)
	// defer C.free(unsafe.Pointer(cstr))

	err = C.pe_load_file(&ctx, cstr)
	if err != C.LIBPE_E_OK {
		C.pe_error_print(C.stderr, err)
		return
	}

	err = C.pe_parse(&ctx)
	if err != C.LIBPE_E_OK {
		C.pe_error_print(C.stderr, err)
		return
	}

	if !C.pe_is_pe(&ctx) {
		return
	}

	result := &Result{}

	result = header_coff(ctx, result)
	result = header_dos(ctx, result)
	result = header_optional(ctx, result)
	result.Directories_count = header_directories_count(ctx)
	result = header_directories(ctx, result)
	result = header_sections(ctx, result)
	result.Sections_count = header_sections_count(ctx)

	// TODO: as each of these are independent, we can use concurrency.

	f_response.Header().Set("Content-Type", "text/json; charset=utf-8")
	json2http := json.NewEncoder(f_response)

	if err := json2http.Encode(result); err != nil {
		http.Error(f_response, "Generating JSON failed", 500)
		info.Println("JSON encoding failed", err.Error())
		return
	}

	elapsed_time := time.Since(start_time)
	info.Printf("Done, total time elapsed %s.\n", elapsed_time)
}

func header_coff(ctx C.pe_ctx_t, temp_result *Result) *Result {
	coff := C.pe_coff(&ctx)

	temp_result.Coff.Machine = int(coff.Machine)
	temp_result.Coff.NumberOfSections = int(coff.NumberOfSections)
	temp_result.Coff.TimeDateStamp = int(coff.TimeDateStamp)
	temp_result.Coff.PointerToSymbolTable = int(coff.PointerToSymbolTable)
	temp_result.Coff.NumberOfSymbols = int(coff.NumberOfSymbols)
	temp_result.Coff.SizeOfOptionalHeader = int(coff.SizeOfOptionalHeader)
	temp_result.Coff.Characteristics = int(coff.Characteristics)

	return temp_result
}

func header_dos(ctx C.pe_ctx_t, temp_result *Result) *Result {
	dos := C.pe_dos(&ctx)

	temp_result.Dos.Magic = int(dos.e_magic)
	temp_result.Dos.Cblp = int(dos.e_cblp)
	temp_result.Dos.Cp = int(dos.e_cp)
	temp_result.Dos.Crlc = int(dos.e_crlc)
	temp_result.Dos.Cparhdr = int(dos.e_cparhdr)
	temp_result.Dos.Minalloc = int(dos.e_minalloc)
	temp_result.Dos.Maxalloc = int(dos.e_maxalloc)
	temp_result.Dos.Ss = int(dos.e_ss)
	temp_result.Dos.Sp = int(dos.e_sp)
	temp_result.Dos.Csum = int(dos.e_csum)
	temp_result.Dos.Ip = int(dos.e_ip)
	temp_result.Dos.Cs = int(dos.e_cs)
	temp_result.Dos.Lfarlc = int(dos.e_lfarlc)
	temp_result.Dos.Ovno = int(dos.e_ovno)
	temp_result.Dos.Res = int(dos.e_res[3])
	temp_result.Dos.Oemid = int(dos.e_oemid)
	temp_result.Dos.Oeminfo = int(dos.e_oeminfo)
	temp_result.Dos.Res2 = int(dos.e_res2[9])
	temp_result.Dos.Lfanew = int(dos.e_lfanew)

	return temp_result
}

func header_optional(ctx C.pe_ctx_t, temp_result *Result) *Result {
	optional := C.pe_optional(&ctx)

	temp_result.Optional.Magic = int(optional.Magic)
	temp_result.Optional.MajorLinkerVersion = int(optional.MajorLinkerVersion)
	temp_result.Optional.MinorLinkerVersion = int(optional.MinorLinkerVersion)
	temp_result.Optional.SizeOfCode = int(optional.SizeOfCode)
	temp_result.Optional.SizeOfInitializedData = int(optional.SizeOfInitializedData)
	temp_result.Optional.SizeOfUninitializedData = int(optional.SizeOfUninitializedData)
	temp_result.Optional.AddressOfEntryPoint = int(optional.AddressOfEntryPoint)
	temp_result.Optional.BaseOfCode = int(optional.BaseOfCode)
	temp_result.Optional.ImageBase = int(optional.ImageBase)
	temp_result.Optional.SectionAlignment = int(optional.SectionAlignment)
	temp_result.Optional.FileAlignment = int(optional.FileAlignment)
	temp_result.Optional.MajorOperatingSystemVersion = int(optional.MajorOperatingSystemVersion)
	temp_result.Optional.MinorOperatingSystemVersion = int(optional.MinorOperatingSystemVersion)
	temp_result.Optional.MajorImageVersion = int(optional.MajorImageVersion)
	temp_result.Optional.MinorImageVersion = int(optional.MinorImageVersion)
	temp_result.Optional.MajorSubsystemVersion = int(optional.MajorSubsystemVersion)
	temp_result.Optional.MinorSubsystemVersion = int(optional.MinorSubsystemVersion)
	temp_result.Optional.Reserved1 = int(optional.Reserved1)
	temp_result.Optional.SizeOfImage = int(optional.SizeOfImage)
	temp_result.Optional.SizeOfHeaders = int(optional.SizeOfHeaders)
	temp_result.Optional.CheckSum = int(optional.CheckSum)
	temp_result.Optional.Subsystem = int(optional.Subsystem)
	temp_result.Optional.DllCharacteristics = int(optional.DllCharacteristics)
	temp_result.Optional.SizeOfStackReserve = int(optional.SizeOfStackReserve)
	temp_result.Optional.SizeOfStackCommit = int(optional.SizeOfStackCommit)
	temp_result.Optional.SizeOfHeapReserve = int(optional.SizeOfHeapReserve)
	temp_result.Optional.SizeOfHeapCommit = int(optional.SizeOfHeapCommit)
	temp_result.Optional.LoaderFlags = int(optional.LoaderFlags)
	temp_result.Optional.NumberOfRvaAndSizes = int(optional.NumberOfRvaAndSizes)

	return temp_result
}

func header_directories_count(ctx C.pe_ctx_t) int {
	directories_count := C.pe_directories_count(&ctx)
	return int(directories_count)
}

func header_directories(ctx C.pe_ctx_t, temp_result *Result) *Result {
	directories := C.pe_directories(&ctx)
	temp_result.Directories.VirtualAddress = int((*directories).VirtualAddress) // returns Virutal address
	temp_result.Directories.Size = int((*directories).Size)
	return temp_result
}

func header_sections_count(ctx C.pe_ctx_t) int {
	sections_count := C.pe_sections_count(&ctx)
	return int(sections_count)
}

func header_sections(ctx C.pe_ctx_t, temp_result *Result) *Result {
	sections := C.pe_sections(&ctx)
	temp_result.Sections.VirtualAddress = int((*sections).VirtualAddress)
	temp_result.Sections.PointerToRawData = int((*sections).PointerToRawData)
	temp_result.Sections.PointerToRelocations = int((*sections).PointerToRelocations) // always zero in executables
	temp_result.Sections.PointerToLinenumbers = int((*sections).PointerToLinenumbers) //deprecated
	temp_result.Sections.NumberOfRelocations = int((*sections).NumberOfRelocations)
	temp_result.Sections.NumberOfLinenumbers = int((*sections).NumberOfLinenumbers) //deprecated
	temp_result.Sections.Characteristics = int((*sections).Characteristics)

	return temp_result

}
