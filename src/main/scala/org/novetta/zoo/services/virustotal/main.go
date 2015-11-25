package main

import (
	"bytes"
	"crypto/md5"
	"encoding/json"
	"errors"
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

const (
	// Your VT ApiKey
	ApiKey               = "APIKEY"
	UploadUnknownSamples = true

	HttpBinding = ":7710"
)

var (
	Client = &http.Client{}
	Info   *log.Logger
)

func main() {
	Info = log.New(os.Stdout, "", log.Ltime|log.Lshortfile)
	Info.Println("Start listening", HttpBinding)

	router := httprouter.New()
	router.GET("/:file", handler)
	log.Fatal(http.ListenAndServe(HttpBinding, router))
}

func NotFound(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	Info.Println("NotFound")
	http.NotFound(w, r)
}

func InternalServerError(w http.ResponseWriter, r *http.Request, err error) {
	Info.Println("Error: ", err.Error())

	w.WriteHeader(http.StatusInternalServerError)
	fmt.Fprint(w, "500 - "+err.Error())
}

func handler(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	f := "/tmp/" + ps.ByName("file")
	if _, err := os.Stat(f); os.IsNotExist(err) {
		http.NotFound(w, r)
		return
	}

	Info.Println("Handling", f)

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

	Info.Println("Done!")
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
	if vtr.ResponseCode == 0 && UploadUnknownSamples {
		hash, err = uploadSample(fPath)
		if err != nil {
			return "", err
		}

		vtr.ResponseCode = 2
	}

	if vtr.ResponseCode == 2 {
		Info.Println("Not done, sleep for 5min")
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
	Info.Println("getReport")

	var respBody []byte

	form := url.Values{}
	form.Add("resource", md5)
	form.Add("apikey", ApiKey)

	req, err := http.NewRequest("POST", "https://www.virustotal.com/vtapi/v2/file/report", strings.NewReader(form.Encode()))
	req.PostForm = form
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err := Client.Do(req)
	if err != nil {
		return respBody, err
	}
	defer resp.Body.Close()

	respBody, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return respBody, err
	}

	Info.Println(string(respBody))

	return respBody, nil
}

func uploadSample(fPath string) (string, error) {
	Info.Println("uploadSample")

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

	err = writer.WriteField("apikey", ApiKey)
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

	resp, err := Client.Do(request)
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

	vtr := &VTResponse{}
	if err := json.Unmarshal(respBody, vtr); err != nil {
		return "", err
	}

	if vtr.ResponseCode != 1 {
		return "", errors.New(vtr.VerboseMsg)
	}

	Info.Println(string(respBody))

	return vtr.ScanId, nil
}