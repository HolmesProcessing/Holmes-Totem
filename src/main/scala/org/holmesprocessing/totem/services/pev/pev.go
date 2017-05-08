package main

import (
	//Imports for measuring execution time of requests
	"time"

	//Imports for reading the config, logging and command line argument parsing.
	"bufio"
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

	//Imports for request execution.
	"os/exec"

	// Import to reduce service memory footprint
	"runtime/debug"
)

type Result struct {
	Magicnumber              string    `json:"MagicNumber"`
	Linkermajorversion       string    `json:"MajorLinkerVersion"`
	Linkerminorversion       string    `json:"MinorLinkerVersion"`
	Sizeoftextsection        string `json:"SizeOfTextSection"`
	Sizeofdatasection        string `json:"SizeOfDataSection"`
	Sizeofbsssection         string `json:"SizeOfBssSection"`
	Entrypoint               string `json:"Entrypoint"`
	Addressoftextsection     string `json:"Addressoftextsection"`
	Addressofdatasection     string `json:"Addressofdatasection"`
	ImageBase                string `json:"Imagebase"`
	Alignmentofsections      string `json:"Alignmentofsection"`
	Alignmentfactor          string `json:"Alignmentfactor"`
	MajorversionofrequiredOS string `json:"majorversionofrequiredos"`
	MinorversionofrequiredOS string `json:"minorversionofrequiredos"`
	Majorversionofimage      string `json:"Majorversionofimage"`
	Minorversionofimage      string `json:"Minorversionofimage"`
	Majorversionofsubsystem  string `json:"MajorVersionofsubsystem"`
	Minorversionofsubsystem  string `json:Minorversionofsubsystem"`
	Sizeofimage              string `json:"Sizeofimage"`
	Sizeofheaders            string `json:"Sizeofheaders"`
	Checksum                 string `json:"Checksum"`
	Subsystemrequired        string `json:"Subsystemrequired"`
	DLLcharacteristics       string `json:"DLLcharacteristics"`
	Sizeofstacktoreserve     string `json:"SizeofStacktoreserve"`
	Sizeofstacktocommit      string `json:"Sizeofstacktocommit"`
	Sizeofheapspacetoreserve string `json:"Sizeofheapspacetoreserve"`
	Sizeofheapspacetocommit  string `json:"Sizeofheapspacetocommit"`
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
	HTTPBinding        string //cvp: saving port is an unnecessary limitation; the binding allows for assigning the IP address too which is nicer
	Options 	   string
}

var (
	pev string
	config    *Config
	info      *log.Logger
	ROPgadget string
	metadata  Metadata = Metadata{
		Name:        "Pev",
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

	// Check if pev is installed
	if binary, err := exec.LookPath("readpe"); err != nil {
		log.Fatalln("Unable to locate readpe binary, is pev installed?", err)
	} else {
		pev = binary
	}

	// setup http handlers
	router := httprouter.New()
	router.GET("/analyze/", handler_analyze)
	router.GET("/", handler_info)

	info.Printf("Binding to %s\n", config.HTTPBinding)
	log.Fatal(http.ListenAndServe(config.HTTPBinding, router))
}

// Parse a configuration file into a Config structure.

func step( line *bufio.Scanner )  []string {
	line.Scan()
	lineSplit := strings.Split(line.Text(), ":")
	temp := lineSplit[1]
	lineSplit[1] = strings.Split(temp, "(")[0]
	lineSplit[1] = strings.TrimSpace(lineSplit[1])
	return lineSplit
}

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

	process := exec.Command(pev, "--header", config.Options, sample_path)
	stdout, err := process.StdoutPipe()
	if err != nil {
		http.Error(f_response, "Creating stdout pipe failed", 500)
		info.Println(err)
		return
	}

	// ms-xy: manually getting the stdin and closing it might not be relevant to
	// this memleak, but it helped with objdump's, doing it as a preemptive measure
	stdin, err := process.StdinPipe()
	if err != nil {
		http.Error(f_response, "Creating stdin pipe failed", 500)
		info.Println(err)
		return
	}
	stdin.Close()

	if err := process.Start(); err != nil {
		http.Error(f_response, "Executing ropgadget failed", 500)
		info.Printf("Error executing ropgadget (file: %s):", sample_path)
		info.Println(err)
		return
	}

	line := bufio.NewScanner(stdout)

	result := &Result{}

	// Sanity check for the first line
	line.Scan()
	if line.Text() != "Optional/Image header" {
		http.Error(f_response, "Executing readpe failed", 500)
		info.Printf("First line failed check: %s", line.Text())
		return
	}
	// read the line just consisting of '=' and throw it away
	// now read all the headers

	lineSplit := step(line)
	result.Magicnumber  = lineSplit[1]
	lineSplit = step(line)
	result.Linkermajorversion = lineSplit[1]
	lineSplit = step(line)
	result.Linkerminorversion = lineSplit[1]
	lineSplit = step(line)
	result.Sizeoftextsection = lineSplit[1]
	lineSplit = step(line)
	result.Sizeofdatasection = lineSplit[1]
	lineSplit = step(line)
	result.Sizeofbsssection = lineSplit[1]
	lineSplit = step(line)
	result.Entrypoint = lineSplit[1]
	lineSplit = step(line)
	result.Addressoftextsection = lineSplit[1]
	lineSplit = step(line)
	result.Addressofdatasection = lineSplit[1]
	lineSplit = step(line)
	result.ImageBase = lineSplit[1]
	lineSplit = step(line)
	result.Alignmentofsections = lineSplit[1]
	lineSplit = step(line)
	result.Alignmentfactor = lineSplit[1]
	lineSplit = step(line)
	result.MajorversionofrequiredOS = lineSplit[1]
	lineSplit = step(line)
	result.MinorversionofrequiredOS = lineSplit[1]
	lineSplit = step(line)
	result.Majorversionofimage = lineSplit[1]
	lineSplit = step(line)
	result.Minorversionofimage = lineSplit[1]
	lineSplit = step(line)
	result.Majorversionofsubsystem = lineSplit[1]
	lineSplit = step(line)
	result.Minorversionofsubsystem = lineSplit[1]
	lineSplit = step(line)
	result.Sizeofimage = lineSplit[1]
	lineSplit = step(line)
	result.Sizeofheaders = lineSplit[1]
	lineSplit = step(line)
	result.Checksum = lineSplit[1]
	lineSplit = step(line)
	result.Subsystemrequired = lineSplit[1]
	lineSplit = step(line)
	result.DLLcharacteristics = lineSplit[1]
	line.Scan()
	lineSplit = step(line)
	result.Sizeofstacktoreserve = lineSplit[1]
	lineSplit = step(line)
	result.Sizeofstacktocommit = lineSplit[1]
	lineSplit = step(line)
	result.Sizeofheapspacetoreserve = lineSplit[1]
	lineSplit = step(line)
	result.Sizeofheapspacetocommit = lineSplit[1]



	if lineErr := line.Err(); err != nil || lineErr != nil {
		http.Error(f_response, "Reading ropgadget output failed", 500)
		info.Println(err)
		return
	}

	f_response.Header().Set("Content-Type", "text/json; charset=utf-8")
	json2http := json.NewEncoder(f_response)

	if err := json2http.Encode(result); err != nil {
		http.Error(f_response, "Generating JSON failed", 500)
		info.Println("JSON encoding failed", err.Error())
		return
	}

	elapsed_time := time.Since(start_time)
	info.Printf("Done, total time elapsed %s.\n",  elapsed_time)
}
