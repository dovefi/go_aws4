package s3api

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	iSO8601FormatDateTime = "20060102T150405Z" // 时间原点
	iSO8601FormatDate     = "20060102"
	dAlgorithm            = "AWS4-HMAC-SHA256"
	dRegion               = "us-east-1"
	dService              = "s3"
	dRequestType          = "aws4_request"
	wrap                  = "\n"
	unSignPayload         = "UNSIGNED-PAYLOAD" // 如果不对BODY进行哈希

)

type S3Key struct {
	accessKey string
	secretKey string
}

type S3Service struct {
	region      string
	service     string
	requestType string
	signPayload bool 	// 是否对body 哈希
}

func NewS3key(access, secret string) *S3Key {
	return &S3Key{accessKey: access, secretKey: secret}
}

func NewS3Service(region, service string, signPayload bool) *S3Service {
	s3s := &S3Service{
		region:      region,
		service:     service,
		requestType: dRequestType,
		signPayload: signPayload,
	}

	if region == "" {
		s3s.region = dRegion
	}

	if service == "" {
		s3s.service = dService
	}
	return s3s
}

func (s3s *S3Service) Signature(s3k *S3Key, r *http.Request) error {
	var err error
	// 如果request 指定了Date 头
	date := r.Header.Get("Date")
	t := time.Now().UTC()
	if date != "" {
		//t, err = time.Parse(http.TimeFormat, date)

		t, err = time.Parse(iSO8601FormatDateTime, date)
		if err != nil {
			return err
		}
	}

	auth, err := s3s.Authorization(t, s3k, r)
	if err != nil {
		return err
	}
	//fmt.Println("add Authorization")

	r.Header.Add("Authorization", auth)
	return nil
}

// Authorization 头
func (s3s *S3Service) Authorization(t time.Time, s3k *S3Key, r *http.Request) (string, error) {
	var err error
	credentialScope := fmt.Sprintf("%s/%s/%s/%s",
		t.Format(iSO8601FormatDate),
		s3s.region, s3s.service,
		s3s.requestType)

	signHeaders := s3s.canonicalSignHeaders(r)
	sign, err := s3s.finalSign(t, s3k, r)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%s Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		dAlgorithm,
		s3k.accessKey,
		credentialScope,
		signHeaders,
		sign), nil
}

// 得出最终的签名结果
func (s3s *S3Service) finalSign(t time.Time, s3k *S3Key, r *http.Request) (string, error) {
	signKey := s3s.signKSecret(t, s3k)
	strToSign, err := s3s.stringToSign(t, r)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", gHmac(signKey, []byte(strToSign))), nil
}

// 创建待签名字符串
func (s3s *S3Service) stringToSign(t time.Time, r *http.Request) (string, error) {
	credentialScope := fmt.Sprintf("%s/%s/%s/%s",
		t.Format(iSO8601FormatDate),
		s3s.region, s3s.service,
		s3s.requestType)

	hr, err := s3s.hashRequest(r)
	if err != nil {
		return "", err
	}

	return dAlgorithm + "\n" +
		t.Format(iSO8601FormatDateTime) + "\n" +
		credentialScope + "\n" +
		hr, nil
}

func (s3s *S3Service) hashRequest(r *http.Request) (string, error) {
	canonReq, err := s3s.canonicalRequest(r)
	if err != nil {
		return "", err
	}
	return gSha256([]byte(canonReq)), nil
}

// 构建规范的请求字符串
func (s3s *S3Service) canonicalRequest(r *http.Request) (string, error) {
	var err error
	httpMethod := strings.ToUpper(r.Method)
	canonURI := s3s.canonicalURI(r)
	signHeader := s3s.canonicalSignHeaders(r)

	canonQuery, err := s3s.canonicalQueryString(r)
	if err != nil {
		return "", err
	}

	canonHeader, err := s3s.canonicalHeaders(r)
	if err != nil {
		return "", err
	}
	var payload string
	if s3s.signPayload {
		payload, err = s3s.hashPayload(r)
		if err != nil {
			return "", err
		}
	} else {
		payload = unSignPayload
	}

	return httpMethod + "\n" +
		canonURI + "\n" +
		canonQuery + "\n" +
		canonHeader + "\n" +
		signHeader + "\n" +
		payload, nil
}

// 规范uri
func (s3s *S3Service) canonicalURI(r *http.Request) string {
	path := r.URL.RequestURI()
	//if strings.Contains(path, "?") {
	//	set := strings.Split(path, "?")
	//	if len(path) > 0 {
	//		path = set[0]
	//	}
	//}

	if r.URL.RawQuery != "" {
		path = path[:len(path)-len(r.URL.RawQuery)-1]
	}
	slash := strings.HasSuffix(path, "/")
	path = filepath.Clean(path)
	if path != "/" && slash {
		path += "/"
	}
	return path
}

// 将url中的请求参数按照参数名
// 升序排序, 如果一个参数有多个值，按照值排序
func (s3s *S3Service) canonicalQueryString(r *http.Request) (string, error) {
	err := r.ParseForm()
	if err != nil {
		return "", err
	}
	queryString := r.Form
	kvs := make([]string, 0, len(queryString))
	for k, vs := range queryString {
		for _, v := range vs {
			if v == "" {
				kvs = append(kvs, url.QueryEscape(k))
			} else {
				kvs = append(kvs, url.QueryEscape(k)+"="+url.QueryEscape(v))
			}
		}
	}

	sort.Strings(kvs)
	return strings.Join(kvs, "&"), nil
}

// 规范化header
func (s3s *S3Service) canonicalHeaders(r *http.Request) (string, error) {
	header := r.Header
	// 将header的值转为字符串，字符串内连续的空格替换为一个空格
	canonValue := func(values []string) (string, error) {
		var vals string
		// 2个以上的空格替换为一个空格，这个很容易忘记处理
		re, err := regexp.Compile("\\s{2,}")
		if err != nil {
			return "", err
		}

		for i, v := range values {
			vals += strings.TrimSpace(re.ReplaceAllString(v, " "))
			if i < (len(values) - 1) {
				vals += "; "
			}
		}
		return vals, nil
	}

	// 获取keys并排序
	keys := make([]string, 0, len(header))
	for k := range header {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var canonHeader string
	for _, k := range keys {
		canVal, err := canonValue(header[k])
		if err != nil {
			return "", err
		}
		canonHeader += strings.ToLower(k) + ":" + canVal + "\n"
	}
	return canonHeader, nil
}

// 这里将加入到签名的header名称拼凑起来
// 目的是为了让服务端知道是基于哪几个header进行签名
func (s3s *S3Service) canonicalSignHeaders(r *http.Request) (string) {
	header := r.Header
	keys := make([]string, 0, len(header))
	for k := range header {
		keys = append(keys, strings.ToLower(k))
	}
	sort.Strings(keys)
	return strings.Join(keys, ";")
}

// 规范request body 进行sha256哈希
func (s3s *S3Service) hashPayload(r *http.Request) (string, error) {
	if r.Body == nil {
		// 如果request 的body 为空，那就用空字符串代替
		return gSha256([]byte("")), nil
	}

	// Getbody 返回body的拷贝，这样不会导致body 被关闭需要重新设置
	bodyCp, err := r.GetBody()
	if err != nil {
		return "", err
	}
	body, err := ioutil.ReadAll(bodyCp)
	if err != nil {
		return "", err
	}
	fmt.Println("hashPayload", gSha256(body))
	return gSha256(body), nil
}

// 将秘钥加入到sign中
func (s3s *S3Service) signKSecret(t time.Time, s3k *S3Key) []byte {
	kDate := gHmac([]byte("AWS4"+s3k.secretKey), []byte(t.Format(iSO8601FormatDate)))
	kRegion := gHmac(kDate, []byte(s3s.region))
	kService := gHmac(kRegion, []byte(s3s.service))
	kSigning := gHmac(kService, []byte(s3s.requestType))
	return kSigning
}

func gSha256(data []byte) string {
	h := sha256.New()
	h.Write(data)
	return fmt.Sprintf("%x", h.Sum(nil))
}

func gHmac(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

