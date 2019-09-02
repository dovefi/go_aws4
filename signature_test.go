package s3api

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"
	"time"
)

// 测试GetObject 接口
func TestGetObject(t *testing.T) {
	client := &http.Client{}

	// s3 用户 access key 和 secret key
	s3k := NewS3key("admin", "admin")
	s3s := NewS3Service("", "", false)
	host := "172.26.2.41:8000"
	url := "http://172.26.2.41:8000/data_bucket/lion.gif"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		panic(nil)
	}
	var content string
	if s3s.signPayload {
		content = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	} else {
		content = unSignPayload
	}
	req.Header.Add("x-amz-content-sha256", content)
	req.Header.Add("Host", host)
	req.Header.Add("x-amz-date", time.Now().UTC().Format(iSO8601FormatDateTime))
	err = s3s.Signature(s3k, req)
	if err != nil {
		panic(err)
	}
	fmt.Println(req.Header)
	resp, err := client.Do(req)
	defer resp.Body.Close()
	if err != nil {
		panic(err)
	}
	fmt.Println(resp.StatusCode)
}

// 测试单块上传
func TestPutObject(t *testing.T) {
	client := &http.Client{}
	s3k := NewS3key("admin", "admin")
	
	// s3 用户 access key 和 secret key
	s3s := NewS3Service("", "", true)
	host := "172.26.2.41:8000"
	url := "http://172.26.2.41:8000/data_bucket/helloGo3.txt"
	content := "hello Golang\n"
	req, err := http.NewRequest("PUT", url, strings.NewReader(content))
	if err != nil {
		panic(err)
	}

	if s3s.signPayload {
		signPayload, err := s3s.hashPayload(req)
		if err != nil {
			panic(err)
		}
		req.Header.Add("x-amz-content-sha256", signPayload)
	} else {
		req.Header.Add("x-amz-content-sha256", unSignPayload)
	}
	req.Header.Add("x-amz-storage-class", "REDUCED_REDUNDANCY")
	req.Header.Add("Host", host)
	req.Header.Add("x-amz-date", time.Now().UTC().Format(iSO8601FormatDateTime))
	err = s3s.Signature(s3k, req)
	if err != nil {
		panic(err)
	}
	//req.Body = ioutil.NopCloser(strings.NewReader(content))
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}

	fmt.Println(resp.StatusCode)
	//body, _ := ioutil.ReadAll(resp.Body)
	//fmt.Println(string(body))
}
