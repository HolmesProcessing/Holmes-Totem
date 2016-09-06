package main

//cvp: merged imports, looks cleaner
import (
	//Imports for messuring execution time of requests
	"time"

	//Imports for reading the config, logging and command line argument parsing.
	"bufio"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	//Imports for serving on a socket and handling routing of incoming request.
	"encoding/json"
	"github.com/julienschmidt/httprouter"
	"net/http"

	//Imports for request execution.
	"os/exec"
)

type Result struct {
	UniqueGadgets int       `json:"total_unique_gadgets"`
	Truncated     bool      `json:"truncated"`
	SearchDepth   int       `json:"search_depth"`
	Gadgets       []*Gadget `json:"gadgets,omitempty"`
}

type Gadget struct {
	Offset       string   `json:"offset,omitempty"`
	Instructions []string `json:"instructions,omitempty"`
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
	MaxNumberOfGadgets int
	SearchDepth        int
}

var (
	config    *Config
	info      *log.Logger
	ROPgadget string
	metadata Metadata = Metadata {
		Name        : "GoGadget",
		Version     : "1.0",
		Description : "./README.md",
		Copyright   : "Copyright 2016 Holmes Group LLC",
		License     : "./LICENSE",
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

	// find ROPgadget binary path
	if binary, err := exec.LookPath("ROPgadget"); err != nil {
		log.Fatalln("Unable to locate ROPgadget binary, is ROPgadget installed?", err)
	} else {
		ROPgadget = binary
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

	process := exec.Command(ROPgadget, "--depth", strconv.Itoa(config.SearchDepth), "--binary", sample_path)
	stdout, err := process.StdoutPipe()
	if err != nil {
		http.Error(f_response, "Creating stdout pipe failed", 500)
		info.Println(err)
		return
	}

	if err := process.Start(); err != nil {
		http.Error(f_response, "Executing ropgadget failed", 500)
		info.Printf("Error executing ropgadget (file: %s):", sample_path)
		info.Println(err)
		return
	}

	line := bufio.NewScanner(stdout)

	result := &Result{
		UniqueGadgets: 0,
		Truncated:     false,
		SearchDepth:   config.SearchDepth,
		Gadgets:       make([]*Gadget, config.MaxNumberOfGadgets),
	}

	// Sanity check for the first line
	line.Scan()
	if line.Text() != "Gadgets information" {
		http.Error(f_response, "Executing ropgadget failed", 500)
		info.Printf("First line failed check: %s", line.Text())
		return
	}
	// read the line just consisting of '=' and throw it away
	line.Scan()

	// now read all the gadgets
	gadgetCounter := 0
	for line.Scan() {
		if line.Text() == "" {
			// if the line is empty we are done with gadgets and
			// only "Unique gadgets found:" is left after this
			break
		}

		// this is not yet optimal, need to run a comparision against regex
		lineSplit := strings.Split(line.Text(), " : ")
		result.Gadgets[gadgetCounter] = &Gadget{
			Offset:       lineSplit[0],
			Instructions: strings.Split(lineSplit[1], " ; "),
		}

		// did we reach the maximum?
		gadgetCounter += 1
		if gadgetCounter == config.MaxNumberOfGadgets {
			result.Truncated = true
			break
		}
	}

	if result.Truncated {
		// if we reached the max amount of gadgets and breaked we need to throw the rest away
		for line.Text() != "" {
			line.Scan()
		}
	} else {
		// if not, we need to throw away the unused array slices
		result.Gadgets = result.Gadgets[:gadgetCounter]
	}

	// now lets get the unique gadgets count
	line.Scan()
	result.UniqueGadgets, err = strconv.Atoi(line.Text()[22:])

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
	info.Printf("Done, read a total of %d gadgets in %s.\n", result.UniqueGadgets, elapsed_time)
}
