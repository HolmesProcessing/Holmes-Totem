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
	"strconv"
	"strings"
)

var (
	config   *Config
	info     *log.Logger
	pdfparse string
	metadata Metadata = Metadata{
		Name:        "pdfparse",
		Version:     "0.1",
		Description: "./README.md",
		Copyright:   "Copyright 2017 Holmes Group LLC",
		License:     "./LICENSE",
	}
)

type Result struct {
	Truncated      bool      `json:"Truncated"`
	Comments       int       `json:"Comments"`
	XREF           int       `json:"XREF"`
	Trailer        int       `json:"Trailer"`
	StartXref      int       `json:"StartXref"`
	IndirectObject int       `json:"IndirectObjects"`
	Objects        []*Object `json:"Objects"`
}

type Object struct {
	Category string `json:"Category"`
	Values   []int  `json:"Values"`
}

// Config structs
type Setting struct {
	HTTPBinding string `json:"HTTPBinding"`
}

type PDFParse struct {
	MaxNumberOfObjects int `json:"MaxNumberOfObjects"`
}

type Config struct {
	Settings Setting  `json:"settings"`
	Logic    PDFParse `json:"pdfparse"`
}

type Metadata struct {
	Name        string
	Version     string
	Description string
	Copyright   string
	License     string
}

func main() {

	var (
		err        error
		configPath string
	)
	info = log.New(os.Stdout, "", log.Ltime|log.Lshortfile)

	flag.StringVar(&configPath, "config", "", "Path to the configuration file")
	flag.Parse()

	config, err = load_config(configPath)
	if err != nil {
		log.Fatalln("Couldn't decode config file without errors!", err.Error())
	}

	router := httprouter.New()
	router.GET("/analyze/", handler_analyze)
	router.GET("/", handler_info)
	info.Printf("Binding to %s\n", config.Settings.HTTPBinding)
	log.Fatal(http.ListenAndServe(config.Settings.HTTPBinding, router))
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

func handler_analyze(f_response http.ResponseWriter, request *http.Request, params httprouter.Params) {
	obj := request.URL.Query().Get("obj")
	if obj == "" {
		http.Error(f_response, "Missing argument 'obj'", 400)
		return
	}
	sample_path := "/tmp/" + obj
	if _, err := os.Stat(sample_path); os.IsNotExist(err) {
		http.NotFound(f_response, request)
		//info.Printf("Error accessing sample (file: %s):", sample_path)
		//info.Println(err)
		return
	}
	process := exec.Command("pdfparse", "--stats", sample_path)

	stdout, err := process.StdoutPipe()
	if err != nil {
		fmt.Println(err)
		return
	}

	stdin, err := process.StdinPipe()
	if err != nil {
		fmt.Println(err)
		return
	}
	stdin.Close()

	if err := process.Start(); err != nil {
		fmt.Println(err)
		return
	}

	line := bufio.NewScanner(stdout)

	// taking first five lines
	var final [5]int
	for i := 0; i < 5; i++ {
		line.Scan()
		lineSplit := strings.Split(line.Text(), ": ")
		final[i], err = strconv.Atoi(lineSplit[1])
	}

	result := &Result{
		Truncated:      false,
		Comments:       final[0],
		XREF:           final[1],
		Trailer:        final[2],
		StartXref:      final[3],
		IndirectObject: final[4],
		Objects:        make([]*Object, config.Logic.MaxNumberOfObjects),
	}

	counter := 0

	for line.Scan() {
		var values = []int{}
		lineSplit := strings.Split(line.Text(), ": ")
		name := lineSplit[0]
		value := strings.Split(lineSplit[1], ", ")

		// convert this array of strings to array of integers
		for _, i := range value {
			j, err := strconv.Atoi(i)
			if err != nil {
				panic(err)
			}
			values = append(values, j)
		}

		result.Objects[counter] = &Object{
			Category: name[1 : len(name)-2],
			Values:   values,
		}
		counter++

		if counter == config.Logic.MaxNumberOfObjects {
			result.Truncated = true
			break
		}
	}

	if result.Truncated {
		// if we reached the max amount of objects and breaked we need to throw the rest away
		for line.Text() != "" {
			line.Scan()
		}
	} else {
		// if not, we need to throw away the unused array slices
		result.Objects = result.Objects[:counter]
	}

	f_response.Header().Set("Content-Type", "text/json; charset=utf-8")
	json2http := json.NewEncoder(f_response)

	if err := json2http.Encode(result); err != nil {
		http.Error(f_response, "Generating JSON failed", 500)
		return
	}
}
