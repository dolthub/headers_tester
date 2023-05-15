package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"golang.org/x/net/http2"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
)

var host = flag.String("host", "", "host of server")
var port = flag.Int("port", 0, "port of server")
var withHeader = flag.String("header", "", "header used for request, ie 'Range: bytes=0-100'")
var withParams = flag.String("params", "", "url encoded query params used for request, ie 'range=bytes%3D0%2D100'")
var allContents = flag.Bool("all", false, "request all contents")
var verbose = flag.Bool("verbose", false, "log verbosely")
var useHttp2 = flag.Bool("http2", false, "use http2")
var insecure = flag.Bool("tls-skip-verify", false, "tls skip verify")
var certFile = flag.String("tls-cert-file", "", "path to tls cert file")
var keyFile = flag.String("tls-key-file", "", "path to tls key file")

const contentMax = 4000

var sampleRangeStart = "bytes=0-1000"
var sampleRangeMid = "bytes=2500-2599"
var sampleRangeEnd = "bytes=-80"

var sampleRanges = map[string]int{
	sampleRangeStart: 1001,
	sampleRangeMid:   100,
	sampleRangeEnd:   80,
}

var sampleParamsStart = "range=bytes%3D0%2D1000"
var sampleParamsMid = "range=bytes%3D2500%2D2599"
var sampleParamsEnd = "range=bytes%3D%2D80"

var sampleParams = map[string]int{
	sampleParamsStart: 1001,
	sampleParamsMid:   100,
	sampleParamsEnd:   80,
}

func main() {
	flag.Parse()
	if *host == "" {
		fmt.Println("must supply --host")
		os.Exit(1)
	}
	if *port == 0 {
		fmt.Println("must supply --port")
		os.Exit(1)
	}

	url := fmt.Sprintf("http://%s:%d", *host, *port)
	client := getDefaultClient(*useHttp2)

	var err error
	if *insecure && *certFile == "" && *keyFile == "" {
		url, client, err = skipVerifyUrlAndClient(*host, *port, *useHttp2)
	} else if *certFile != "" && *keyFile != "" {
		url, client, err = secureUrlAndClient(*host, *certFile, *keyFile, *port, *useHttp2)
	}
	if err != nil {
		panic(err)
	}

	if *withHeader != "" {
		_, _, err = sendWithHeader(client, url, *withHeader, *verbose)
	} else if *withParams != "" {
		_, _, err = sendWithParams(client, url, *withParams, *verbose)
	} else if *allContents {
		_, _, err = sendRaw(client, url, *verbose)
	} else {
		err = sendSamples(client, url, *verbose)
	}
	if err != nil {
		panic(err)
	}
}

func sendSamples(client *http.Client, url string, vbs bool) error {
	// request ranges with range header
	for headerBytes, expectedLen := range sampleRanges {
		header := "Range: " + headerBytes
		actualStatus, actualLen, err := sendWithHeader(client, url, header, vbs)
		if err != nil {
			return err
		}
		if actualStatus != http.StatusPartialContent {
			fmt.Printf("did not receive expected status: url: %s header: %s expected: %d actual: %d", url, header, http.StatusPartialContent, actualStatus)
		}
		if actualLen != expectedLen {
			fmt.Printf("requested bytes did not match bytes served: url: %s header: %s requested: %d served: %d", url, header, expectedLen, actualLen)
		}
	}

	// request ranges with x-dolt-range header
	for headerBytes, expectedLen := range sampleRanges {
		header := "x-dolt-range: " + headerBytes
		actualStatus, actualLen, err := sendWithHeader(client, url, header, vbs)
		if err != nil {
			return err
		}
		if actualStatus != http.StatusPartialContent {
			fmt.Printf("did not receive expected status: url: %s header: %s expected: %d actual: %d", url, header, http.StatusPartialContent, actualStatus)
		}
		if actualLen != expectedLen {
			fmt.Printf("requested bytes did not match bytes served: url: %s header: %s requested: %d served: %d", url, header, expectedLen, actualLen)
		}
	}

	// request ranges with params
	for params, expectedLen := range sampleParams {
		actualStatus, actualLen, err := sendWithParams(client, url, params, vbs)
		if err != nil {
			return err
		}
		if actualStatus != http.StatusPartialContent {
			fmt.Printf("did not receive expected status: url: %s params: %s expected: %d actual: %d", url, params, http.StatusPartialContent, actualStatus)
		}
		if actualLen != expectedLen {
			fmt.Printf("requested bytes did not match bytes served: url: %s params: %s requested: %d served: %d", url, params, expectedLen, actualLen)
		}
	}

	// request all contents
	actualStatus, actualLen, err := sendRaw(client, url, vbs)
	if err != nil {
		return err
	}
	if actualStatus != http.StatusOK {
		fmt.Printf("did not receive expected status: url: %s expected: %d actual: %d", url, http.StatusOK, actualStatus)
	}
	if actualLen != contentMax {
		fmt.Printf("requested bytes did not match bytes served: url: %s requested: %d served: %d", url, contentMax, actualLen)
	}

	return nil
}

func sendRaw(client *http.Client, url string, vbs bool) (int, int, error) {
	req, err := http.NewRequest(http.MethodGet, url, http.NoBody)
	if err != nil {
		return 0, 0, err
	}
	return send(client, req, vbs)
}

func sendWithParams(client *http.Client, url, params string, vbs bool) (int, int, error) {
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/?%s", url, params), http.NoBody)
	if err != nil {
		return 0, 0, err
	}
	return send(client, req, vbs)
}

func sendWithHeader(client *http.Client, url, header string, vbs bool) (int, int, error) {
	req, err := http.NewRequest(http.MethodGet, url, http.NoBody)
	if err != nil {
		return 0, 0, err
	}

	parts := strings.Split(header, ":")
	if len(parts) != 2 {
		return 0, 0, errors.New("failed to parse header")
	}

	key := strings.TrimSpace(parts[0])
	value := strings.TrimSpace(parts[1])

	if key != "Range" && key != "range" && key != "x-dolt-range" && key != "X-Dolt-Range" {
		return 0, 0, errors.New("unsupported header, only 'Range'|'range' and 'X-Dolt-Range'|'x-dolt-range' supported")
	}

	req.Header.Add(key, value)
	return send(client, req, vbs)
}

func send(client *http.Client, req *http.Request, vbs bool) (int, int, error) {
	fmt.Println("request:")
	for name, headers := range req.Header {
		for _, hdr := range headers {
			fmt.Printf("with header: '%s: %s'\n", name, hdr)
		}
	}

	for key, value := range req.URL.Query() {
		fmt.Printf("with url query param: '%s=%s'", key, value)
	}

	fmt.Println()
	res, err := client.Do(req)
	if err != nil {
		return 0, 0, err
	}
	defer res.Body.Close()

	fmt.Println("response:")
	fmt.Println("status:", res.Status)
	for name, headers := range res.Header {
		for _, hdr := range headers {
			fmt.Printf("with header: '%s: %s'\n", name, hdr)
		}
	}

	b, err := io.ReadAll(res.Body)
	if err != nil {
		return 0, 0, err
	}

	if vbs {
		fmt.Println("body (base64):", base64.StdEncoding.EncodeToString(b))
		fmt.Println()
	}

	fmt.Println()
	return res.StatusCode, len(b), nil
}

func getDefaultClient(useHttp2 bool) *http.Client {
	client := http.DefaultClient
	if useHttp2 {
		client = &http.Client{
			Transport: &http2.Transport{
				// So http2.Transport doesn't complain the URL scheme isn't 'https'
				AllowHTTP: true,
				// Pretend we are dialing a TLS endpoint. (Note, we ignore the passed tls.Config)
				DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
					return net.Dial(network, addr)
				},
			},
		}
	}
	return client
}
func skipVerifyUrlAndClient(host string, port int, useHttp2 bool) (string, *http.Client, error) {
	url := fmt.Sprintf("https://%s:%d", host, port)
	t := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{Transport: t}

	if useHttp2 {
		client = &http.Client{
			Transport: &http2.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		}
	}

	return url, client, nil
}

func secureUrlAndClient(host, certFile, keyFile string, port int, useHttp2 bool) (string, *http.Client, error) {
	url := fmt.Sprintf("https://%s:%d", host, port)

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return "", nil, fmt.Errorf("error creating x509 keypair from client cert file %s and client key file %s", certFile, keyFile)
	}

	caCert, err := os.ReadFile(certFile)
	if err != nil {
		return "", nil, err
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			RootCAs:      caCertPool,
		},
	}}

	if useHttp2 {
		client = &http.Client{
			Transport: &http2.Transport{
				TLSClientConfig: &tls.Config{
					Certificates: []tls.Certificate{cert},
					RootCAs:      caCertPool,
				},
			},
		}
	}

	return url, client, nil
}
