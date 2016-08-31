package client

import (
    "github.com/antonholmquist/jason"
    "net/http"
    "time"
)

// This object contains the users credentials as well as the query value and a
// http.Client reference. Please use client.New(user, apikey, object, timeout)
// for proper instantiation.
type Client struct {
    username string
    apikey   string
    obj      string
    client   *http.Client
}

// Creates a new client.Client and returns its reference.
func New(username, apikey string, timeout int) *Client {
    self := &Client{}
    self.username = username
    self.apikey = apikey
    self.client = &http.Client{Timeout: time.Duration(timeout) * time.Second}
    return self
}

// The typical result of all public query functions on the client.Client object.
// Not all fields may be set. Fields are set in the following order:
// - HttpError
// - StatusCode, Status
// - JsonError
// - Error, ErrorMessage, DeveloperMessage || Json
type ApiResult struct {
    QueryDescription string
    HttpError        error
    StatusCode       int
    Status           string
    JsonError        error
    Json             interface{}
    Error            bool
    ErrorMessage     string
    DeveloperMessage string
}

// Send a request using the supplied authentication tokens.
// Returns an ApiResult that needsto be checked for errors and messages.
func (self *Client) SendApiRequest(url, description string) *ApiResult {
    apiResult := &ApiResult{}
    apiResult.QueryDescription = description
    apiResult.Error = false

    r, _ := http.NewRequest("GET", url, nil)
    r.SetBasicAuth(self.username, self.apikey)

    httpResponse, httpError := self.client.Do(r)
    if httpError != nil {
        apiResult.HttpError = httpError
        return apiResult
    }

    apiResult.StatusCode = httpResponse.StatusCode
    apiResult.Status = httpResponse.Status

    jsonResponse, jsonError := jason.NewObjectFromReader(httpResponse.Body)
    if jsonError != nil {
        apiResult.JsonError = jsonError
        return apiResult
    }
    apiResult.Json = jsonResponse
    httpResponse.Body.Close()

    obj, notFoundError := jsonResponse.GetObject("error")
    if notFoundError == nil {
        apiResult.Error = true
        apiResult.ErrorMessage = jasonGetString(obj, "message")
        apiResult.DeveloperMessage = jasonGetString(obj, "developer_message")
    }

    return apiResult
}
