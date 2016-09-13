package main

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/julienschmidt/httprouter"
)

type VTResponse struct {
	ResponseCode int    `json:"response_code"`
	ScanId       string `json:"scan_id"`
	VerboseMsg   string `json:"verbose_msg"`
}

// config structs
type Metadata struct {
	Name        string
	Version     string
	Description string
	Copyright   string
	License     string
}

//TODO: unifying info url. saving cvp's comments from gogadget as they should be addressed
type Config struct {
	HTTPBinding          string //cvp: saving port is an unnecessary limitation; the binding allows for assigning the IP address too which is nicer
	ApiKey               string
	UploadUnknownSamples bool
	RequestTimeout       int
}

var (
	config   *Config
	info     *log.Logger
	client   *http.Client
	metadata Metadata = Metadata{
		Name:        "VirusTotal",
		Version:     "1.0",
		Description: "./README.md",
		Copyright:   "Copyright 2016 Holmes Group LLC",
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
	flag.StringVar(&configPath, "config", "", "Path to the config file")
	flag.Parse()

	config, err = load_config(configPath)
	if err != nil {
		info.Fatalln("Couldn't decode config file without errors!", err.Error())
	}
	client = &http.Client{Timeout: time.Duration(config.RequestTimeout) * time.Second}

	router := httprouter.New()
	router.GET("/analyze/", handler_analyze)
	router.GET("/", handler_info)
	info.Printf("Binding to %s\n", config.HTTPBinding)
	info.Fatal(http.ListenAndServe(config.HTTPBinding, router))
}

func NotFound(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	info.Println("Cannot find file!")
	http.NotFound(w, r)
}

func InternalServerError(w http.ResponseWriter, r *http.Request, err error) {
	info.Println("Error: ", err.Error())

	w.WriteHeader(http.StatusInternalServerError)
	fmt.Fprint(w, "500 - "+err.Error())
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

	// validate ApiKey
	_, err := hex.DecodeString(config.ApiKey)
	if len(config.ApiKey) != 64 || err != nil {
		info.Println("Apikey seems to be invalid! Please supply a valid key!")
		return config, err
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

func handler_analyze(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	info.Println("Serving request:", r)

	obj := r.URL.Query().Get("obj")
	if obj == "" {
		http.Error(w, "Missing argument 'obj'", 400)
		return
	}
	//TODO: Remove error if file isn't found. File isn't needed unless upload is specified
	f := "/tmp/" + obj
	if _, err := os.Stat(f); os.IsNotExist(err) {
		http.NotFound(w, r)
		return
	}

	//TODO: VT will now accept sha256 or md5. Maybe adjust or just use filename
	hash, err := CalculateMD5(f)
	if err != nil {
		InternalServerError(w, r, err)
		return
	}

	result, err := vtWork(fmt.Sprintf("%x", hash), f)
	if err != nil {
		InternalServerError(w, r, err)
		return
	}

	fmt.Fprint(w, result)
}

func vtWork(hash, fPath string) (string, error) {
	report, err := getReport(hash)
	if err != nil {
		return "", err
	}

	vtr := &VTResponse{}
	if err := json.Unmarshal(report, vtr); err != nil {
		return "", err
	}

	// 0 = unknwon
	// 1 = found
	// 2 = processing
	if vtr.ResponseCode == 0 && config.UploadUnknownSamples {
		hash, err = uploadSample(fPath)
		if err != nil {
			return "", err
		}

		vtr.ResponseCode = 2
	}

	if vtr.ResponseCode == 2 {
		info.Println("Not done, sleep for 5min")
		time.Sleep(time.Minute * 5)
		return vtWork(hash, fPath)
	}

	return string(report), nil
}

func CalculateMD5(filePath string) ([]byte, error) {
	var result []byte
	file, err := os.Open(filePath)
	if err != nil {
		return result, err
	}
	defer file.Close()

	hash := md5.New()
	if _, err := io.Copy(hash, file); err != nil {
		return result, err
	}

	return hash.Sum(result), nil
}

func getReport(md5 string) ([]byte, error) {
	info.Println("getReport")

	var respBody []byte

	form := url.Values{}
	form.Add("resource", md5)
	form.Add("apikey", config.ApiKey)

	req, err := http.NewRequest("POST", "https://www.virustotal.com/vtapi/v2/file/report", strings.NewReader(form.Encode()))
	req.PostForm = form
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return respBody, err
	}
	defer resp.Body.Close()

	respBody, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return respBody, err
	}

	info.Println("VT responded: ", resp.Status)

	if string(respBody) == "" {
		return respBody, errors.New("VT Get Report Response is empty! " + resp.Status)
	}

	return respBody, nil
}

func uploadSample(fPath string) (string, error) {
	info.Println("uploadSample")

	file, err := os.Open(fPath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	body := new(bytes.Buffer)
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("file", filepath.Base(fPath))
	if err != nil {
		return "", err
	}
	_, err = io.Copy(part, file)

	err = writer.WriteField("apikey", config.ApiKey)
	if err != nil {
		return "", err
	}

	err = writer.Close()
	if err != nil {
		return "", err
	}

	request, err := http.NewRequest("POST", "https://www.virustotal.com/vtapi/v2/file/scan", body)
	if err != nil {
		return "", err
	}
	request.Header.Add("Content-Type", writer.FormDataContentType())

	resp, err := client.Do(request)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", err
	}

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	info.Println(resp.Status)
	info.Println(string(respBody))

	if string(respBody) == "" {
		return "", errors.New("VT Upload Response is empty! " + resp.Status)
	}

	vtr := &VTResponse{}
	if err := json.Unmarshal(respBody, vtr); err != nil {
		return "", err
	}

	if vtr.ResponseCode != 1 {
		return "", errors.New(vtr.VerboseMsg)
	}

	info.Println(string(respBody))

	return vtr.ScanId, nil
}
