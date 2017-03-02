package main

import (
	//"time"
	"io/ioutil"
	"path/filepath"
	"fmt"
	"bufio"
	"encoding/json"
	//"runtime/debug"
	"os"
	"os/exec"
	"flag"
	"strconv"
	"strings"
	"github.com/julienschmidt/httprouter"
	"net/http"	
	"log"
	
)

var (
	config    *Config
	info      *log.Logger
	pdfparse string
	metadata  Metadata = Metadata{
		Name:        "pdfparse",
		Version:     "0.1",
		Description: "./README.md",
		Copyright:   "Copyright 2017 Holmes Group LLC",
		License:     "./LICENSE",
	}
)

type Result struct {
	Comments int `json:"Comments"`
	XREF int	`json:"XREF"`
	Trailer int	`json:"Trailer"`
	StartXref int	`json:"StartXref"`
	IndirectObject int `json:"IndirectObject"`
}
type Config struct {
	HTTPBinding string
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
		err error
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
	info.Printf("Binding to %s\n", config.HTTPBinding)
	log.Fatal(http.ListenAndServe(config.HTTPBinding, router))
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
	process := exec.Command("pdfparse","--stats",sample_path)
	
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
	counter := 0
	var final [5]int
	for line.Scan() {
		lineSplit := strings.Split(line.Text(), ": ")
		final[counter], err = strconv.Atoi(lineSplit[0])
		counter++
	}

	result := &Result {
		Comments: final[0],
		XREF : final[1],
		Trailer : final[2],
		StartXref : final[3],
		IndirectObject : final[4],
	}

	f_response.Header().Set("Content-Type", "text/json; charset=utf-8")
	json2http := json.NewEncoder(f_response)

	if err := json2http.Encode(result); err != nil {
		http.Error(f_response, "Generating JSON failed", 500)
		//info.Println("JSON encoding failed", err.Error())
		return
	}
}