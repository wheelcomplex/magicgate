// A multiple function gateway include http/https/dns server with auto let's encrypt (by certmagic)

package main

// Todo: alt http port as a backend for reverse proxy, dns challenge, reverse proxy

import (
	"crypto/tls"
	"expvar"
	"flag"
	"fmt"
	"log"
	"magicgate"
	"net"
	"os"
	"strings"

	"github.com/buaazp/fasthttprouter"
	"github.com/caddyserver/certmagic"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/expvarhandler"
	"go.uber.org/zap"
	"golang.org/x/crypto/acme"
)

var (
	ctlToken           = flag.String("ctltoken", "", "a token to control server from client, URI: /api/ctl/shutdown/*token")
	trimList           = flag.String("trimlist", "", "redirect www.example.com or blog.example.com to example.com, when --trimlist=www,blog")
	runProd            = flag.Bool("prod", false, "run on production environment")
	addr               = flag.String("addr", "0.0.0.0:80", "TCP address to listen for HTTP")
	addrAlt            = flag.String("addralt", "0.0.0.0:9080", "alternate TCP address to listen for HTTP, as backend for reverse proxy")
	addrTLS            = flag.String("addrTLS", "0.0.0.0:443", "TCP address to listen to TLS (aka SSL or HTTPS) requests. Leave empty for disabling TLS")
	byteRange          = flag.Bool("byteRange", true, "Enables byte range requests if set to true")
	compress           = flag.Bool("compress", true, "Enables transparent response compression if set to true")
	docRoot            = flag.String("docroot", "/var/www", "Directory to serve static files from")
	generateIndexPages = flag.Bool("generateIndexPages", true, "Whether to generate directory index pages")
	certDir            = flag.String("certdir", "./.magicgate/cert/", "Path to cache cert")
	vhost              = flag.Bool("vhost", false, "Enables virtual hosting by prepending the requested path with the requested hostname")
	certDomains        = flag.String("domains", "", "Domain list for ssl cert, empty or * for all domains, *.example.com for wildcard sub-domains")
	defaultServerName  = flag.String("defaultservername", "certmagic.default.server.example.com", "Default server name for ssl cert when not servername supply from client")
	certEmail          = flag.String("certemail", "", "Administrator Email for cert")
)

var (
	certDomainList         = []string{}
	certWildcardDomainList = []string{}

	trimPrefixList = [][]byte{}
)

func main() {

	logger := zap.NewExample()
	defer logger.Sync()

	// Parse command-line flags.
	flag.Parse()

	for _, item := range strings.Split(magicgate.LoopReplaceAll(*certDomains, " ", ","), ",") {
		if len(item) == 0 {
			continue
		}
		if magicgate.IsAllDotNumber(item) {
			log.Printf("CERTDOMAINS, SKIPPED, can not use IP address as tls domain: %s\n", item)
			continue
		}
		if strings.HasPrefix(item, "*.") {
			item = magicgate.LoopReplaceAll(item, "*.", "")
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
	for _, item := range strings.Split(magicgate.LoopReplaceAll(*trimList, " ", ","), ",") {
		if len(item) == 0 {
			continue
		}
		if strings.HasSuffix(item, ".") {
			item = magicgate.LoopReplaceAll(item, ".", "")
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

	// use certmagic default cache

	// if the decision function returns an error, a certificate
	// may not be obtained for that name at that time
	certmagic.Default.OnDemand = &certmagic.OnDemandConfig{
		DecisionFunc: func(name string) error {
			// Todo: more effection way to check for massive domains
			for _, oneDomain := range certDomainList {
				if name == oneDomain {
					log.Printf("certmagic, DecisionFunc match normal domain: %s\n", name)
					return nil
				}
				log.Printf("certmagic, DecisionFunc MISMATCH normal domain (%s): %s\n", oneDomain, name)
			}
			for _, oneDomain := range certWildcardDomainList {
				if strings.HasSuffix(name, oneDomain) {
					log.Printf("certmagic, DecisionFunc match WILDCARD domain (*%s): %s\n", oneDomain, name)
					return nil
				}
				log.Printf("certmagic, DecisionFunc MISMATCH WILDCARD domain (*%s): %s\n", oneDomain, name)
			}
			log.Printf("certmagic, DecisionFunc not allowed domain: %s\n", name)
			return fmt.Errorf("certmagic, not allowed domain: %s", name)
		},
	}

	myCertMagic := certmagic.NewDefault()

	// if the decision function returns an error, a certificate
	// may not be obtained for that name at that time

	myCertMagic.DefaultServerName = *defaultServerName

	myCertMagic.Storage = &certmagic.FileStorage{Path: *certDir}

	myACME := certmagic.NewACMEManager(myCertMagic, certmagic.ACMEManager{
		CA:     certmagic.LetsEncryptStagingCA,
		Email:  *certEmail,
		Agreed: true,
		Logger: logger,
		// plus any other customizations you need
	})

	if *runProd {
		log.Printf("certmagic running on LetsEncryptProductionCA\n")
		myACME.CA = certmagic.LetsEncryptProductionCA
	} else {
		log.Printf("certmagic running on LetsEncryptStagingCA\n")
	}

	myCertMagic.Issuer = myACME

	//
	redirectHandler := &magicgate.RedirectHandler{
		Counter:  1,
		CtlToken: []byte(*ctlToken),
	}

	// http routing
	// handler ACME or redirect to tls
	httpRouter := fasthttprouter.New()
	httpRouter.GET("/stats", expvarhandler.ExpvarHandler)
	httpRouter.GET("/stat", expvarhandler.ExpvarHandler)
	httpRouter.GET("/.well-known/acme-challenge/*token", redirectHandler.HTTPChallengeHandler(myACME, nil))
	// catch-all to redirect
	httpRouter.NotFound = redirectHandler.RedirectToTLSHandler()
	// or trim prefix and redirect to tls
	// httpRouter.NotFound = redirectHandler.PrefixTLSRedirectHandler(trimPrefixList)

	//
	tlsServiceHandler := func(ctx *fasthttp.RequestCtx) {
		fsHandler(ctx)
		updateFSCounters(ctx)
	}

	tlsRouter := fasthttprouter.New()
	tlsRouter.GET("/stats", expvarhandler.ExpvarHandler)
	tlsRouter.GET("/api/ctl/shutdown/:token", redirectHandler.ServerControlHandler)
	// catch-all to trim prefix or service
	tlsRouter.NotFound = tlsServiceHandler

	// try to redirect first and goto router
	// tlsRouterHandler := redirectHandler.MagicRedirectHandler(redirectHandler.PrefixRedirectHandler(trimPrefixList, nil), tlsRouter.Handler)
	// or redirect without magic redirect info
	tlsRouterHandler := redirectHandler.PrefixRedirectHandler(trimPrefixList, tlsRouter.Handler)

	// Start HTTP server.
	if len(*addr) > 0 {
		log.Printf("Starting HTTP server on %q", *addr)

		go func() {
			if err := fasthttp.ListenAndServe(*addr, httpRouter.Handler); err != nil {
				log.Fatalf("error in ListenAndServe: %s", err)
			}
		}()
	}

	// alternate HTTP server, use tlsServiceHandler
	if len(*addrAlt) > 0 {
		log.Printf("Starting Alternate HTTP server on %q", *addrAlt)

		go func() {
			if err := fasthttp.ListenAndServe(*addrAlt, tlsServiceHandler); err != nil {
				log.Fatalf("error in ListenAndServe: %s", err)
			}
		}()
	}

	// Start HTTPS server.
	if len(*addrTLS) > 0 {
		log.Printf("Starting HTTPS server on %q", *addrTLS)

		if err := os.MkdirAll(*certDir, 0700); err != nil {
			log.Fatalf("error in create cert dir: %s", err)
		}

		// TLS specific general settings
		cfg := &tls.Config{
			MinVersion:     tls.VersionTLS12,
			GetCertificate: certmagic.NewDefault().GetCertificate,
			NextProtos: []string{
				"http/1.1", acme.ALPNProto,
			},
		}
		// get cfg for tls finally

		// Let's Encrypt tls-alpn-01 only works on port 443.
		ln, err := net.Listen("tcp4", *addrTLS)
		if err != nil {
			panic(err)
		}

		lnTLS := tls.NewListener(ln, cfg)
		go func() {
			if err := fasthttp.Serve(lnTLS, tlsRouterHandler); err != nil {
				panic(err)
			}
		}()
	}

	log.Printf("Serving files from directory %q", *docRoot)
	log.Printf("See stats at http://%s/stats", *addr)
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
