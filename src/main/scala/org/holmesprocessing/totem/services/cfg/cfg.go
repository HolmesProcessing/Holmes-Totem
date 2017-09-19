package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/julienschmidt/httprouter"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

var (
	config   *Config
	info     *log.Logger
	nucleus  string
	metadata Metadata = Metadata{
		Name:        "cfg",
		Version:     "0.1",
		Description: "./README.md",
		Copyright:   "Copyright 2017 Holmes Group LLC",
		License:     "./LICENSE",
	}
)

type Arc struct {
	Tail       string  `json:"tail"`
	Head       string  `json:"head"`
	Label      string  `json:"label"`
}

type Result struct {
	Truncated  bool    `json:"truncated"`
	Arcs       []*Arc  `json:"arcs"`
}

// Config Structs
type Setting struct {
	HTTPBinding string `json:"HTTPBinding"`
}

type CFG struct {
	MaxNumberOfArcs int `json:"MaxNumberOfArcs"`
}

type Config struct {
	Settings Setting `json:"settings"`
	Cfg CFG `json:"cfg"`
}

type Metadata struct {
	Name        string
	Version     string
	Description string
	Copyright   string
	License     string
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

func check(err error) {
	if err != nil {
		fmt.Println(err)
		return
	}
}

func deleteFile(path string) {
	var err = os.Remove(path)
	check(err)
}

func split(r rune) bool {
	return r == '>' || r == '['
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

	dot_path := "/data" + sample_path + ".dot"
	process := exec.Command(nucleus, "-d", "linear", "-f", "-p", "-e", sample_path, "-g", dot_path)

	// We are not interested in the output of the command, just the errors and the written output in the dot files
	if _, err := process.CombinedOutput(); err != nil {
		info.Printf("Error running nucleus sample: %s", err.Error())
		return
    }

	file, err := os.Open(dot_path)
	check(err)
	defer file.Close()
	line := bufio.NewScanner(file)

	result := &Result{
		Truncated: false,
		Arcs:      make([]*Arc, config.Cfg.MaxNumberOfArcs),
	}

	/* Example file
	digraph G {

	bb_401000 -> bb_40e716 [ label="jmp" ];
	bb_401010 -> bb_40e716 [ label="call" ];
	bb_401010 -> bb_40101e [ label="fallthrough" ];
	bb_40101e -> bb_40102b [ label="jmp/+3" ];
	[...]
	}
	*/

	// Sanity check for the first line
	line.Scan()
	if line.Text() != "digraph G {" {
		http.Error(f_response, "Executing nucleus failed", 500)
		info.Printf("First line failed check: %s", line.Text())
		return
	}

	counter := 0

	for line.Scan() {
		if (line.Text() == "}") || (line.Text() == "") {
			continue
		}

		a := strings.FieldsFunc(line.Text(), split)
		t := strings.TrimSpace(strings.TrimSuffix(a[0], "-"))
		h := strings.TrimSpace(a[1])
		l := strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(a[2]), "label=\""), "\" ];")

		result.Arcs[counter] = &Arc{
			Tail:  t,
			Head:  h,
			Label: l,
		}

		counter++

		if counter == config.Cfg.MaxNumberOfArcs {
			result.Truncated = true
			break
		}
	}

	if result.Truncated {
		// if we reach the max amount of arcs and break, we'll need to throw the rest away
		for line.Text() != "" {
			line.Scan()
		}
	} else {
		// if not, we'll need to throw away the unused array slices
		result.Arcs = result.Arcs[:counter]
	}

	f_response.Header().Set("Content-Type", "text/json; charset=utf-8")
	json2http := json.NewEncoder(f_response)

	if err := json2http.Encode(result); err != nil {
		http.Error(f_response, "Generating JSON failed", 500)
		return
	}

	deleteFile(dot_path)

	elapsed_time := time.Since(start_time)
	info.Printf("Elapsed time: %s\n", elapsed_time)
}

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

	// set nucleus binary path
	nucleus = "./nucleus/nucleus"
	if _, err := os.Stat(nucleus); os.IsNotExist(err) {
		log.Fatalln("Unable to locate nucleus binary, is nucleus installed?", err)
	}

	// setup http handlers
	router := httprouter.New()
	router.GET("/analyze/", handler_analyze)
	router.GET("/", handler_info)

	info.Printf("Binding to %s\n", config.Settings.HTTPBinding)
	log.Fatal(http.ListenAndServe(config.Settings.HTTPBinding, router))
}
