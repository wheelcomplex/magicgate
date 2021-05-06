// A multiple function gateway include http/https/dns server with auto let's encrypt (by certmagic)

package main

// Todo: reverse proxy, remote ip register/datacache

import (
	"crypto/tls"
	"expvar"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/buaazp/fasthttprouter"
	"github.com/caddyserver/certmagic"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/expvarhandler"
	"github.com/wheelcomplex/lumberjack"
	"github.com/wheelcomplex/magicgate"
	"github.com/wheelcomplex/magicgate/utils"
	"github.com/wheelcomplex/multiproxy"
	"go.uber.org/zap"
	"golang.org/x/crypto/acme"
)

var (
	proxyList          = flag.String("proxylist", "", "tcp/udp proxy, list format: <tcp|udp>:<frontend address>:<backend address|passive token>, address should be host:port, \npassive token use for backend connect to frontend")
	ctrlToken          = flag.String("ctrltoken", "", "a token to control server from client, URI: /api/ctrl/shutdown/*token")
	trimList           = flag.String("trimlist", "", "redirect www.example.com or blog.example.com to example.com, when --trimlist=www,blog")
	runProd            = flag.Bool("prod", false, "run on production environment")
	addr               = flag.String("addr", "0.0.0.0:8080", "TCP address to listen for HTTP")
	addrAlt            = flag.String("addrAlt", "0.0.0.0:9080", "alternate TCP address to listen for HTTP, as backend for reverse proxy")
	addrTLS            = flag.String("addrTLS", "0.0.0.0:8443", "TCP address to listen to TLS (aka SSL or HTTPS) requests. Leave empty for disabling TLS")
	byteRange          = flag.Bool("byteRange", true, "Enables byte range requests if set to true")
	compress           = flag.Bool("compress", true, "Enables transparent response compression if set to true")
	docRoot            = flag.String("docroot", "/var/www", "Directory to serve static files from")
	generateIndexPages = flag.Bool("generateIndexPages", true, "Whether to generate directory index pages")
	certDir            = flag.String("certdir", "./.magicgate/cert/", "Path to cache cert")
	cacheDir           = flag.String("cachedir", "./.magicgate/fastcache/", "Path to fastcache")
	logDir             = flag.String("logdir", "./log/", "Path to save log")
	vhost              = flag.Bool("vhost", false, "Enables virtual hosting by prepending the requested path with the requested hostname")
	certDomains        = flag.String("domains", "", "Domain list for ssl cert, empty or * for all domains, *.example.com for wildcard sub-domains")
	defaultServerName  = flag.String("defaultservername", "", "Default server name for ssl cert when not servername supply from client")
	certEmail          = flag.String("certemail", "", "Administrator Email for cert")
	apiTokens          = flag.String("apitoken", "gentoken", "api token list: '<token>:[uid],<token>:[uid]', if set to 'gentoken' will generate 16 tokens for test")
	noHttpRedirect     = flag.Bool("noHttpRedirect", false, "do not redirect http requests to TLS")
)

func main() {

	// Parse command-line flags.
	flag.Parse()

	var logWriter *lumberjack.Logger
	if len(*logDir) > 0 {
		*logDir, _ = filepath.Abs(*logDir)
		log.Printf("LogDir: %s\n", *logDir)
		if err := os.MkdirAll(*logDir, 0700); err != nil {
			log.Fatalf("error in create log dir: %s", err)
		}

		logWriter = &lumberjack.Logger{
			Filename:   *logDir + "/main.log",
			MaxSize:    500, // megabytes
			MaxBackups: 3,
			MaxAge:     28,    //days
			Compress:   false, // disabled by default
		}

		log.Printf("Magicgate v1.0\n")
		log.Printf("%s\n", time.Now().Format("2006-01-02 15:04:05.000000"))

		log.Printf("logging to file: %s\n", logWriter.Filename)
		log.SetOutput(logWriter)
	} else {
		log.Printf("Logging to file disabled.\n")
	}

	log.Printf("Magicgate v1.0\n")
	log.Printf("%s\n", time.Now().Format("2006-01-02 15:04:05.000000"))

	//
	*certDir, _ = filepath.Abs(*certDir)
	log.Printf("CertDir: %s\n", *certDir)
	if err := os.MkdirAll(*certDir, 0700); err != nil {
		log.Fatalf("error in create cert dir: %s", err)
	}
	*cacheDir, _ = filepath.Abs(*cacheDir)
	log.Printf("CacheDir: %s\n", *cacheDir)
	if err := os.MkdirAll(*cacheDir, 0700); err != nil {
		log.Fatalf("error in create fastcache dir: %s", err)
	}

	logger := zap.NewExample()
	defer logger.Sync()

	var (
		certDomainList         = []string{}
		certWildcardDomainList = []string{}

		trimPrefixList = [][]byte{}
	)

	var err error

	// Todo: move args processing to ServerImp init

	// make default server name available
	allDomains := *certDomains + "," + *defaultServerName
	for _, item := range strings.Split(utils.LoopReplaceAll(allDomains, " ", ","), ",") {
		if len(item) == 0 {
			continue
		}
		if strings.HasPrefix(item, "*.") {
			item = utils.LoopReplaceAll(item, "*.", "")
			if len(item) == 0 {
				continue
			}
			certWildcardDomainList = append(certWildcardDomainList, "."+item)
			// append example.com for *.example.com too
			certDomainList = append(certDomainList, item)
		} else {
			certDomainList = append(certDomainList, item)
		}
	}
	for _, item := range certDomainList {
		log.Printf("CERTDOMAINS, NORMAL: %s\n", item)
	}
	for _, item := range certWildcardDomainList {
		log.Printf("CERTDOMAINS, WILDCARD: *%s\n", item)
	}

	// trimList
	for _, item := range strings.Split(utils.LoopReplaceAll(*trimList, " ", ","), ",") {
		if len(item) == 0 {
			continue
		}
		if strings.HasSuffix(item, ".") {
			item = utils.LoopReplaceAll(item, ".", "")
			if len(item) == 0 {
				continue
			}
		}
		item += "."
		trimPrefixList = append(trimPrefixList, []byte(item))
	}
	for _, item := range trimPrefixList {
		log.Printf("TRIM HOST PREFIX: %s\n", item)
	}

	//
	srv := &magicgate.ServerImp{
		Counter:           1,
		CtrlToken:         []byte(*ctrlToken),
		Domains:           certDomainList,
		WildcardDomains:   certWildcardDomainList,
		DefaultServerName: *defaultServerName,
		TrimList:          trimPrefixList,
		// Todo: add command line flags
	}

	// Setup FS handler

	fsPathNotFoundHandler := func(ctx *fasthttp.RequestCtx) {
		// you may want to do more here
		fmt.Fprintf(ctx, "Requested URI (%q) NOT FOUND: %q", ctx.Request.URI().String(), ctx.Path())
		log.Printf("Requested URI NOT FOUND: (%s) %s%s\n", ctx.Request.URI().String(), *docRoot, ctx.Path())
	}

	fs := &fasthttp.FS{
		Root:               *docRoot,
		IndexNames:         []string{"index.html"},
		GenerateIndexPages: *generateIndexPages,
		Compress:           *compress,
		AcceptByteRange:    *byteRange,
		PathNotFound:       fsPathNotFoundHandler,
	}

	if *vhost {
		fs.PathRewrite = fasthttp.NewVHostPathRewriter(0)
	}
	fsHandler := fs.NewRequestHandler()

	tokens := map[string]uint64{}

	if len(*ctrlToken) == 0 {
		*ctrlToken, err = utils.RandToken(16)
		if err != nil {
			log.Fatalf("Generate server control token failed: %v\n", err)
		}
	}
	*ctrlToken = strings.ToLower(*ctrlToken)
	// Note: server token always map to uid 0
	tokens[*ctrlToken] = 0

	log.Printf("SERVER CONTROL TOKEN: %s\n", *ctrlToken)

	if *apiTokens == "gentoken" {
		for i := 0; i < 16; i++ {
			*apiTokens, err = utils.RandToken(16)
			if err != nil {
				log.Fatalf("Generate api token failed: %v\n", err)
			}
			*apiTokens = strings.ToLower(*apiTokens)
			if oldToken, ok := tokens[*apiTokens]; ok {
				log.Fatalf("API TOKEN already existed: %s, %d\n", *apiTokens, oldToken)
			}
			tokens[*apiTokens] = uint64(i) + 1
			log.Printf("API TOKEN#%d: %s, %d\n", i, *apiTokens, tokens[*apiTokens])
		}
	} else {
		var tk, tmpString string
		var uid uint64
		var cnt int = 1 //normal uid start from 1
		*apiTokens = utils.LoopReplaceAll(*apiTokens, " ", "_")
		for _, item := range strings.Split(*apiTokens, ",") {
			if len(item) == 0 {
				continue
			}
			tmp := strings.Split(item, ":")
			if len(tmp) == 0 {
				log.Fatalf("Invalid API TOKEN: %s\n", item)
			}
			cnt++
			if len(tmp) == 1 {
				tk = strings.ToLower(tmp[0])
				tmpString = fmt.Sprintf("%d", cnt)
			} else {
				// len > 1
				tk = strings.ToLower(tmp[0])
				tmpString = tmp[1]
			}
			if uid, err = strconv.ParseUint(tmpString, 10, 64); err == nil {
				if oldToken, ok := tokens[tk]; ok {
					log.Fatalf("API TOKEN already existed: %s, %d\n", tk, oldToken)
				}
				log.Printf("API TOKEN#%d: %s, %d\n", cnt, tk, uid)
				tokens[tk] = uid
			} else {
				log.Printf("Invalid API TOKEN(uid should be unsigned number): %s => %s\n", item, tmpString)
			}
		}
	}

	// load DataCache
	dc, err := magicgate.LoadDataCache(*cacheDir, true, 2*1024*1024)
	if err != nil {
		log.Fatalf("error while load data: %s", err)
	}
	//

	// merge tokens to dataCache
	effected := dc.MergeTokens(tokens, true)
	log.Printf("effected tokens: %v\n", effected)

	// put custom in DefaultACME
	certmagic.DefaultACME.Email = *certEmail

	certmagic.DefaultACME.Agreed = true

	certmagic.DefaultACME.Logger = logger

	// default to stage server
	certmagic.DefaultACME.CA = certmagic.LetsEncryptStagingCA

	// put custom setting to default Config
	certmagic.Default.DefaultServerName = *defaultServerName

	certmagic.Default.Logger = logger

	// if the decision function returns an error, a certificate
	// may not be obtained for that name at that time
	certmagic.Default.OnDemand = &certmagic.OnDemandConfig{
		DecisionFunc: srv.DomainACLNoIP,
	}

	certmagic.Default.Storage = &certmagic.FileStorage{Path: *certDir}

	// certmagic.Default.OnEvent = func(event string, data interface{}) {
	// 	// log.Printf("certmagic.Default.OnEvent: %s, %v\n", event, data)
	// }

	// get my certmagic.Config from default
	myConfig := certmagic.NewDefault()

	myACMEManager := certmagic.NewACMEManager(myConfig, certmagic.DefaultACME)

	myConfig.Issuer = myACMEManager

	if *runProd {
		log.Printf("certmagic running on LetsEncryptProductionCA\n")
		myACMEManager.CA = certmagic.LetsEncryptProductionCA
	} else {
		log.Printf("certmagic running on LetsEncryptStagingCA\n")
	}

	// TLS specific general settings
	tlsCfg := &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: myConfig.GetCertificate,
		NextProtos: []string{
			"http/1.1", acme.ALPNProto,
		},
	}
	// get tlsCfg for tls finally

	// check domain acl
	fileServiceHandler := srv.ServerHandler(func(ctx *fasthttp.RequestCtx) {
		fsHandler(ctx)
		updateFSCounters(ctx)
	})

	// http routing
	// handler ACME or redirect to tls
	httpRouter := fasthttprouter.New()
	httpRouter.GET("/stats", expvarhandler.ExpvarHandler)
	httpRouter.GET("/stat", expvarhandler.ExpvarHandler)
	httpRouter.GET("/.well-known/acme-challenge/*token", srv.FastHTTPChallengeHandler(myACMEManager, nil))
	if *noHttpRedirect {
		log.Printf("HTTP to TLS redirecting disabled\n")

		httpRouter.NotFound = fileServiceHandler

	} else {
		// catch-all to redirect
		httpRouter.NotFound = srv.RedirectToTLSHandler()
		// or trim prefix and redirect to tls
		// httpRouter.NotFound = srv.PrefixTLSRedirectHandler()
	}

	tlsRouter := fasthttprouter.New()
	tlsRouter.GET("/stats", expvarhandler.ExpvarHandler)
	tlsRouter.GET("/api/ctrl/shutdown/:token", srv.ServerControlHandler)

	tlsRouter.GET("/api/db/set/:token/:key/:value", dc.DataCacheSetKVHandler())
	tlsRouter.GET("/api/db/get/:token/:key", dc.DataCacheGetKVHandler())
	// Todo: tlsRouter.POST("/api/db/set/:token", dc.DataCacheJSONHandler())
	tlsRouter.GET("/api/db/list/:token/:key", dc.DataCacheListKVHandler())

	// Todo:
	tlsRouter.GET("/api/db/setproxy/:token/:key/:value", dc.DataCacheSetProxyHandler())

	// catch-all to trim prefix or service
	tlsRouter.NotFound = fileServiceHandler

	// try to redirect first and goto router
	// tlsRouterHandler := srv.MagicServerImp(srv.PrefixRedirectHandler(nil), tlsRouter.Handler)
	// or redirect without magic redirect info
	tlsRouterHandler := srv.PrefixRedirectHandler(tlsRouter.Handler)

	// ignore HUP and PIPE signals
	utils.NoSIGHUP()
	utils.NoSIGPIPE()

	// start proxy server
	if len(*proxyList) > 0 {
		myProxy := multiproxy.NewProxyServer(*proxyList, dc.ProxyAuthHandler(), logWriter)
		log.Printf("Starting Proxy server ...\n")
		for k, v := range myProxy.ForwardInfo() {
			log.Printf("    %s <= %s\n", k, v)
		}
		myProxy.StartProxy()
	}

	// Start HTTP server.
	if len(*addr) > 0 {
		log.Printf("Starting HTTP server on %q\n", *addr)

		go func() {
			if err := fasthttp.ListenAndServe(*addr, srv.ServerHandler(httpRouter.Handler)); err != nil {
				log.Fatalf("error in ListenAndServe: %s", err)
			}
		}()
	}

	// alternate HTTP server, use fileServiceHandler
	if len(*addrAlt) > 0 {
		log.Printf("Starting Alternate HTTP server on %q\n", *addrAlt)

		go func() {
			if err := fasthttp.ListenAndServe(*addrAlt, tlsRouterHandler); err != nil {
				log.Fatalf("error in ListenAndServe: %s\n", err)
			}
		}()
	}

	// Start HTTPS server.
	if len(*addrTLS) > 0 {
		log.Printf("Starting HTTPS server on %q\n", *addrTLS)

		// Let's Encrypt tls-alpn-01 only works on port 443.
		ln, err := net.Listen("tcp4", *addrTLS)
		if err != nil {
			panic(err)
		}

		// apply tlsCfg for tls.NewListener finally
		lnTLS := tls.NewListener(ln, tlsCfg)
		go func() {
			if err := fasthttp.Serve(lnTLS, tlsRouterHandler); err != nil {
				panic(err)
			}
		}()
	}

	if len(*addrAlt) > 0 {
		log.Printf("Serving files from directory %q\n", *docRoot)
		log.Printf("See stats at http://%s/stats\n", *addrAlt)
	}
	// Wait forever.
	select {}
}

//
func updateFSCounters(ctx *fasthttp.RequestCtx) {
	// Increment the number of fsHandler calls.
	fsCalls.Add(1)

	// Update other stats counters
	resp := &ctx.Response
	switch resp.StatusCode() {
	case fasthttp.StatusOK:
		fsOKResponses.Add(1)
		fsResponseBodyBytes.Add(int64(resp.Header.ContentLength()))
	case fasthttp.StatusNotModified:
		fsNotModifiedResponses.Add(1)
	case fasthttp.StatusNotFound:
		fsNotFoundResponses.Add(1)
	default:
		fsOtherResponses.Add(1)
	}
}

// Various counters - see https://golang.org/pkg/expvar/ for details.
var (
	// Counter for total number of fs calls
	fsCalls = expvar.NewInt("fsCalls")

	// Counters for various response status codes
	fsOKResponses          = expvar.NewInt("fsOKResponses")
	fsNotModifiedResponses = expvar.NewInt("fsNotModifiedResponses")
	fsNotFoundResponses    = expvar.NewInt("fsNotFoundResponses")
	fsOtherResponses       = expvar.NewInt("fsOtherResponses")

	// Total size in bytes for OK response bodies served.
	fsResponseBodyBytes = expvar.NewInt("fsResponseBodyBytes")
)
