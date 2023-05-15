package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

var port = flag.Int("port", 1709, "http listening port")
var securePort = flag.Int("secure-port", 443, "https listening port")
var certFile = flag.String("tls-cert-file", "", "path to tls cert file")
var keyFile = flag.String("tls-key-file", "", "path to tls key file")
var verbose = flag.Bool("verbose", false, "log verbosely")

var errInvalidRange = errors.New("invalid range")
var errInvalidRangeStr = errors.New("invalid range string")

func main() {
	flag.Parse()

	if *port == 0 {
		fmt.Println("must supply --port")
		os.Exit(1)
	}

	if *securePort == 0 {
		fmt.Println("must supply --secure-port")
		os.Exit(1)
	}

	if *certFile == "" {
		fmt.Println("must supply --tls-cert-file")
		os.Exit(1)
	}

	if *keyFile == "" {
		fmt.Println("must supply --tls-key-file")
		os.Exit(1)
	}

	httpSrv := getHttpServer(*port, *verbose)

	httpsSrv, err := getHttpsServer(*securePort, *verbose)
	if err != nil {
		panic(err)
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-quit
		signal.Stop(quit)

		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()

		fmt.Println("http server is shutting down")
		if err := httpSrv.Shutdown(ctx); err != nil {
			fmt.Println("failed to shutdown http server", err.Error())
		}

		fmt.Println("https server is shutting down")
		if err := httpsSrv.Shutdown(ctx); err != nil {
			fmt.Println("failed to shutdown https server", err.Error())
		}

	}()

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		fmt.Println("Serving http on :", *port)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Println("Error serving http server:", err.Error())
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		fmt.Println("Serving https on :", *securePort)
		if err := httpsSrv.ListenAndServeTLS(*certFile, *keyFile); err != nil && err != http.ErrServerClosed {
			fmt.Println("Error serving https server:", err.Error())
		}
	}()

	wg.Wait()

}

func serveContents(w http.ResponseWriter, req *http.Request, contents *inMemContents, vbs bool) {
	if req.Method != http.MethodGet {
		w.WriteHeader(http.StatusBadRequest)
		_, err := io.WriteString(w, "only GET requests supported.")
		if err != nil {
			fmt.Println(err.Error())
		}
		fmt.Println("received unsupported request method")
		return
	}

	fmt.Println("received request")

	w.Header().Add("Accept-Ranges", "bytes")

	// handle range header
	rangeHeader := req.Header.Get("Range")
	if rangeHeader == "" {
		rangeHeader = req.Header.Get("range")
	}
	if rangeHeader != "" {
		fmt.Println("header: 'range'")
		writeContentRange(w, contents, rangeHeader, vbs)
		return
	}

	// handle x-dolt-range header
	xRangeHeader := req.Header.Get("X-Dolt-Range")
	if xRangeHeader == "" {
		xRangeHeader = req.Header.Get("x-dolt-range")
	}
	if xRangeHeader != "" {
		fmt.Println("header: 'x-dolt-range'")
		writeContentRange(w, contents, xRangeHeader, vbs)
		return
	}

	// handle query params
	rangeParam := req.URL.Query().Get("Range")
	if rangeParam == "" {
		rangeParam = req.URL.Query().Get("range")
	}
	if rangeParam != "" {
		fmt.Println("query param: 'range'")
		writeContentRange(w, contents, rangeParam, vbs)
		return
	}

	// if there's no range requests, getHttpServer all content
	fmt.Println("for all content")
	b := contents.ReadAll()

	if *verbose {
		fmt.Println("encoded content:", base64.StdEncoding.EncodeToString(b))
	}

	fmt.Println("content-length:", contents.Len())
	fmt.Println("status-code:", http.StatusOK)
	fmt.Println()

	w.Header().Add("Content-Length", strconv.FormatInt(contents.Len(), 10))
	w.WriteHeader(http.StatusOK)

	n, err := w.Write(b)
	if err != nil {
		panic(err)
	}
	if int64(n) != contents.Len() {
		panic("failed to write all contents")
	}
}

func writeContentRange(w http.ResponseWriter, contents *inMemContents, rangeStr string, vbs bool) {
	offset, length, err := offsetAndLenFromRange(rangeStr, int64(contents.Len()))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Println("bad request:", err.Error())
		fmt.Println()
		return
	}

	b, err := contents.ReadRange(offset, offset+length)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Println("bad request:", err.Error())
		fmt.Println()
		return
	}

	fmt.Println("responding:")

	contentRange := fmt.Sprintf("bytes %d-%d/%d", offset, offset+length-1, contents.Len())
	contentLength := fmt.Sprintf("%d", length)
	statusCode := http.StatusPartialContent

	fmt.Println("content-range:", contentRange)
	fmt.Println("content-length:", contentLength)
	fmt.Println("status-code:", statusCode)

	w.Header().Add("Content-Range", contentRange)
	w.Header().Add("Content-Length", contentLength)
	w.WriteHeader(statusCode)

	if vbs {
		fmt.Println("encoded range:", base64.StdEncoding.EncodeToString(b))
		fmt.Println()
	}

	fmt.Println()

	n, err := w.Write(b)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Println("failed to write range:", err.Error())
		fmt.Println()
	}

	if int64(n) != length {
		w.WriteHeader(http.StatusInternalServerError)
		panic(fmt.Sprintf("failed to write partial contents: wrote %d of %d", n, length))
	}
}

func offsetAndLenFromRange(rngStr string, contentSize int64) (int64, int64, error) {
	if rngStr == "" {
		return -1, -1, nil
	}

	if !strings.HasPrefix(rngStr, "bytes=") {
		return -1, -1, errInvalidRangeStr
	}

	tokens := strings.Split(rngStr[6:], "-")
	if len(tokens) != 2 {
		return -1, -1, errInvalidRangeStr
	}

	// handle byte range header of length of N bytes from end of file `bytes=-#`
	if tokens[0] == "" {
		length, err := strconv.ParseUint(strings.TrimSpace(tokens[1]), 10, 64)
		if err != nil {
			return -1, -1, errInvalidRangeStr
		}
		return contentSize - int64(length), int64(length), nil
	}

	// handle byte range header of offset to end of file `bytes=#-`
	if tokens[1] == "" {
		offset, err := strconv.ParseUint(strings.TrimSpace(tokens[0]), 10, 64)
		if err != nil {
			return -1, -1, err
		}
		return int64(offset), int64(contentSize) - int64(offset), nil
	}

	start, err := strconv.ParseUint(strings.TrimSpace(tokens[0]), 10, 64)
	if err != nil {
		return -1, -1, err
	}

	end, err := strconv.ParseUint(strings.TrimSpace(tokens[1]), 10, 64)
	if err != nil {
		return -1, -1, err
	}

	return int64(start), int64(end-start) + 1, nil
}

type inMemContents struct {
	mu       *sync.Mutex
	contents []byte
}

var text = `
platea dictumst quisque sagittis purus sit amet volutpat consequat mauris nunc congue nisi vitae suscipit tellus mauris a diam maecenas sed enim ut sem viverra aliquet eget sit amet tellus cras adipiscing enim eu turpis egestas pretium aenean pharetra magna ac placerat vestibulum lectus mauris ultrices eros in cursus turpis massa tincidunt dui ut ornare lectus sit amet est placerat in egestas erat imperdiet sed euismod nisi porta lorem mollis aliquam ut porttitor leo a diam sollicitudin tempor id eu nisl nunc mi ipsum faucibus vitae aliquet nec ullamcorper sit amet risus nullam eget felis eget nunc lobortis mattis aliquam faucibus purus in massa tempor nec feugiat nisl pretium fusce id velit ut tortor pretium viverra suspendisse potenti nullam ac tortor vitae purus faucibus ornare suspendisse sed nisi lacus sed viverra tellus in hac habitasse platea dictumst vestibulum rhoncus est pellentesque elit ullamcorper dignissim cras tincidunt lobortis feugiat vivamus at augue eget arcu dictum varius duis at consectetur lorem donec massa sapien faucibus et molestie ac feugiat sed lectus vestibulum mattis ullamcorper velit sed ullamcorper morbi tincidunt ornare massa eget egestas purus viverra accumsan in nisl nisi scelerisque eu ultrices vitae auctor eu augue ut lectus arcu bibendum at varius vel pharetra vel turpis nunc eget lorem dolor sed viverra ipsum nunc aliquet bibendum enim facilisis gravida neque convallis a cras semper auctor neque vitae tempus quam pellentesque nec nam aliquam sem et tortor consequat id porta nibh venenatis cras sed felis eget velit aliquet sagittis id consectetur purus ut faucibus pulvinar elementum integer enim neque volutpat ac tincidunt vitae semper quis lectus nulla at volutpat diam ut venenatis tellus in metus vulputate eu scelerisque felis imperdiet proi fermentum leo vel orci porta non pulvinar neque laoreet suspendisse interdum consectetur libero id faucibus nisl tincidunt eget nullam non nisi est sit amet facilisis magna etiam tempor orci eu lobortis elementum nibh tellus molestie nunc non blandit massa enim nec dui nunc mattis enim ut tellus elementum sagittis vitae et leo duis ut diam quam nulla porttitor massa id neque aliquam vestibulum morbi blandit cursus risus at ultrices mi tempus imperdiet nulla malesuada pellentesque elit eget gravida cum sociis natoque penatibus et magnis dis parturient montes nascetur ridiculus mus mauris vitae ultricies leo integer malesuada nunc vel risus commodo viverra maecenas accumsan lacus vel facilisis volutpat est velit egestas dui id ornare arcu odio ut sem nulla pharetra diam sit amet nisl suscipit adipiscing bibendum est ultricies integer quis auctor elit sed vulputate mi sit amet mauris commodo quis imperdiet massa tincidunt nunc pulvinar sapien et ligula ullamcorper malesuada proin libero nunc consequat interdum varius sit amet mattis vulputate enim nulla aliquet porttitor lacus luctus accumsan tortor posuere ac ut consequat semper viverra nam libero justo laoreet sit amet cursus sit amet dictum sit amet justo donec enim diam vulputate ut pharetra sit amet aliquam id diam maecenas ultricies mi eget mauris pharetra et ultrices neque ornare aenean euismod elementum nisi quis eleifend quam adipiscing vitae proin sagittis nisl rhoncus mattis rhoncus urna neque viverra justo nec ultrices dui sapien eget mi proin sed libero enim sed faucibus turpis in eu mi bibendum neque egestas congue quisque egestas diam in arcu cursus euismod quis viverra nibh cras pulvinar mattis nunc sed blandit libero volutpat sed cras ornare arcu dui vivamus arcu felis bibendum ut tristique et egestas quis ipsum suspendisse ultrices gravida dictum fusce ut placerat orci nulla pellentesque dignissim enim sit amet venenatis urna cursus eget nunc scelerisque viverra mauris in aliquam sem fringilla ut morbi tincidunt augue interdum velit euismod in pellentesque massa placerat duis ultricies lacus sed turpis tincidunt id aliquet risus feugiat in ante metus dictum at tempor commodo ullamcorp
`

func newContents() *inMemContents {
	return &inMemContents{
		mu:       &sync.Mutex{},
		contents: []byte(text),
	}
}

func (c *inMemContents) Len() int64 {
	return int64(len(c.contents))
}

func (c *inMemContents) ReadAll() []byte {
	return c.contents[:]
}

func (c *inMemContents) ReadRange(start, end int64) ([]byte, error) {
	if end < start || end > c.Len() || start < 0 {
		return nil, errInvalidRange
	}
	return c.contents[start:end], nil
}

func getHttpServer(port int, vbs bool) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		serveContents(writer, request, newContents(), vbs)
	})

	// support http2
	h2s := &http2.Server{}

	return &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: h2c.NewHandler(mux, h2s),
	}
}

func getHttpsServer(port int, vbs bool) (*http.Server, error) {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		serveContents(writer, request, newContents(), vbs)
	})

	cfg := &tls.Config{
		MinVersion:       tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		},
	}

	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", port),
		Handler:      mux,
		TLSConfig:    cfg,
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0),
	}

	err := http2.ConfigureServer(srv, &http2.Server{})
	if err != nil {
		return nil, err
	}

	return srv, nil
}
