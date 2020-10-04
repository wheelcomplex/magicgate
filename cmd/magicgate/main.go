package main

import (
	"bytes"
	"crypto/tls"
	"expvar"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/fasthttp/router"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/expvarhandler"
	"github.com/valyala/fasthttp/fasthttpadaptor"
	"github.com/wheelcomplex/certmagic"
	"golang.org/x/crypto/acme"
)

var (
	trimwww            = flag.Bool("trimwww", true, "redirect access to www.example.com to example.com")
	runProd            = flag.Bool("prod", false, "run on production environment")
	addr               = flag.String("addr", "0.0.0.0:80", "TCP address to listen for HTTP")
	addrTLS            = flag.String("addrTLS", "0.0.0.0:443", "TCP address to listen to TLS (aka SSL or HTTPS) requests. Leave empty for disabling TLS")
	byteRange          = flag.Bool("byteRange", true, "Enables byte range requests if set to true")
	compress           = flag.Bool("compress", true, "Enables transparent response compression if set to true")
	docRoot            = flag.String("docroot", "/var/www", "Directory to serve static files from")
	generateIndexPages = flag.Bool("generateIndexPages", true, "Whether to generate directory index pages")
	certDir            = flag.String("certdir", "./.magicgate/cert/", "Path to cache cert")
	vhost              = flag.Bool("vhost", false, "Enables virtual hosting by prepending the requested path with the requested hostname")
	certDomains        = flag.String("domains", "", "domain list for ssl cert, empty or * for all domains, *.example.com for wildcard sub-domains")
)

var (
	certDomainList         = []string{} // empty array, not nil
	certWildcardDomainList = []string{} // empty array, not nil
)

// RedirectHandler redirect HTTP requests to HTTPS
type RedirectHandler struct {
	LastURI string
	Counter int64
	mux     sync.Mutex
}

// HTTPChallengeHandler return a fasthttp.RequestHandler which use for handle ACME HTTP challenge,
// only requests to "/.well-known/acme-challenge/" should be route to this handler.
func (h *RedirectHandler) HTTPChallengeHandler(am *certmagic.ACMEManager, next fasthttp.RequestHandler) fasthttp.RequestHandler {
	httpChallengeHandler := fasthttpadaptor.NewFastHTTPHandler(am.HTTPChallengeHandler(nil))
	return func(ctx *fasthttp.RequestCtx) {
		if bytes.HasPrefix(ctx.Path(), []byte("/.well-known/acme-challenge/")) {
			httpChallengeHandler(ctx)
			return
		}
		if next != nil {
			next(ctx)
		}
	}
}

// PrefixRedirectHandler return a fasthttp.RequestHandler which trim the prefix from request host and redirect to new host,
// if prefix not found, will pass request to next handler.
func (h *RedirectHandler) PrefixRedirectHandler(prefix string, next fasthttp.RequestHandler) fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {

		log.Printf("PrefixRedirectHandler: %s, (%s <= %s), requested path is %q(%q). LastURI is %q. Counter is %d", prefix, ctx.LocalAddr(), ctx.RemoteAddr(), ctx.Path(), ctx.Request.URI().String(), h.LastURI, h.Counter)

		h.mux.Lock()

		h.LastURI = string(ctx.Path())
		h.Counter++
		h.mux.Unlock()

		reqHost := ctx.Host()

		if host := bytes.TrimPrefix(reqHost, []byte(prefix)); bytes.Compare(host, reqHost) != 0 {
			// Request host has www. prefix. Redirect to host with www. trimmed.
			// log.Printf("Redirect handler(%s <= %s), requested host: %s, trimmed www.: %s\n", ctx.LocalAddr(), ctx.RemoteAddr(), reqHost, host)

			// https always run on port 443
			ctx.Redirect(string(ctx.URI().Scheme())+"://"+string(host)+string(ctx.RequestURI()), fasthttp.StatusFound)
			log.Printf("PrefixRedirectHandler: %s,(%s <= %s), redirected to %q\n", prefix, ctx.LocalAddr(), ctx.RemoteAddr(), string(ctx.URI().Scheme())+"://"+string(host)+string(ctx.RequestURI()))
			return
		}
		if next != nil {
			next(ctx)
		}
		return
	}
}

// RedirectToTLSHandler return a fasthttp.RequestHandler which redirect a http request to https
func (h *RedirectHandler) RedirectToTLSHandler() fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		log.Printf("RedirectToTLSHandler(%s <= %s), requested path is %q(%q). LastURI is %q. Counter is %d", ctx.LocalAddr(), ctx.RemoteAddr(), ctx.Path(), ctx.Request.URI().String(), h.LastURI, h.Counter)

		// Todo: should we check this ?
		if bytes.Compare(ctx.URI().Scheme(), []byte("https")) == 0 {
			log.Fatalf("can not use RedirectToTLSHandler with tls/https requests")
		}

		h.mux.Lock()
		h.LastURI = string(ctx.Path())
		h.Counter++
		h.mux.Unlock()

		reqHost := ctx.Host()

		var newhost string
		var err error
		newhost, _, err = net.SplitHostPort(string(reqHost))

		if err != nil {
			// not port come with request host
			newhost = string(reqHost)
		}

		// https always run on port 443
		ctx.Redirect("https://"+newhost+string(ctx.RequestURI()), fasthttp.StatusFound)
		log.Printf("RedirectToTLSHandler(%s <= %s), redirected to %q\n", ctx.LocalAddr(), ctx.RemoteAddr(), "https://"+newhost+string(ctx.RequestURI()))
		return
	}
}

// PrefixTLSRedirectHandler return a fasthttp.RequestHandler which redirect a http request to https, and trim the prefix from request host and redirect to new host,
// if prefix not found, will pass request to next handler.
func (h *RedirectHandler) PrefixTLSRedirectHandler(prefix string) fasthttp.RequestHandler {
	return h.PrefixRedirectHandler(prefix, h.RedirectToTLSHandler())
}

func main() {

	// Parse command-line flags.
	flag.Parse()

	for _, item := range strings.Split(loopReplaceAll(*certDomains, " ", ","), ",") {
		if len(item) == 0 {
			continue
		}
		if isAllDotNumber(item) {
			continue
		}
		if strings.HasPrefix(item, "*.") {
			item = loopReplaceAll(item, "*.", "")
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
	for _, oneDomain := range certDomainList {
		log.Printf("CERTDOMAINS, NORMAL: %s\n", oneDomain)
	}
	for _, oneDomain := range certWildcardDomainList {
		log.Printf("CERTDOMAINS, WILDCARD: *%s\n", oneDomain)
	}

	// Setup FS handler
	fs := &fasthttp.FS{
		Root:               *docRoot,
		IndexNames:         []string{"index.html"},
		GenerateIndexPages: *generateIndexPages,
		Compress:           *compress,
		AcceptByteRange:    *byteRange,
		PathNotFound: func(ctx *fasthttp.RequestCtx) {
			fmt.Fprintf(ctx, "Requested URI (%q) NOT FOUND: %q", ctx.Request.URI().String(), ctx.Path())
			// log.Printf("Requested URI NOT FOUND: (%s) %s%s\n", ctx.Request.URI().String(), *docRoot, ctx.Path())
		},
	}

	if *vhost {
		fs.PathRewrite = fasthttp.NewVHostPathRewriter(0)
	}
	fsHandler := fs.NewRequestHandler()

	// Create RequestHandler serving server stats on /stats and files
	// on other requested paths.
	// /stats output may be filtered using regexps. For example:
	//
	//   * /stats?r=fs will show only stats (expvars) containing 'fs'
	//     in their names.
	// httpRequestHandler := func(ctx *fasthttp.RequestCtx) {
	// 	path := ctx.Path()
	// 	if bytes.HasPrefix(path, []byte("/.well-known/acme-challenge/")) {
	// 		certmagicFastHTTPHandler(ctx)
	// 	} else {
	// 		redirectHandler.Handler(ctx)
	// 	}
	// }

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

	certmagic.Default.Storage = &certmagic.FileStorage{Path: *certDir}

	//
	redirectHandler := &RedirectHandler{
		Counter: 1,
	}

	// handler ACME and trim www. prefix, and redirect to tls
	httpRdrHandler := redirectHandler.HTTPChallengeHandler(&certmagic.DefaultACME, redirectHandler.PrefixTLSRedirectHandler("www."))

	tlsServiceHandler := func(ctx *fasthttp.RequestCtx) {
		fsHandler(ctx)
		updateFSCounters(ctx)
	}

	// trim www. and normal service
	tlsHandler := redirectHandler.PrefixRedirectHandler("www.", tlsServiceHandler)

	// http routing
	httpRouter := router.New()
	httpRouter.GET("/stats", expvarhandler.ExpvarHandler)
	httpRouter.GET("/stat", expvarhandler.ExpvarHandler)
	httpRouter.GET("/", httpRdrHandler)

	tlsRouter := router.New()
	tlsRouter.GET("/stats", expvarhandler.ExpvarHandler)
	tlsRouter.GET("/", tlsHandler)

	//
	if !*runProd {
		certmagic.DefaultACME.CA = certmagic.LetsEncryptStagingCA
		log.Printf("certmagic running on LetsEncryptStagingCA\n")
	} else {
		log.Printf("certmagic running on LetsEncryptCA\n")
	}

	// Start HTTP server.
	if len(*addr) > 0 {
		log.Printf("Starting HTTP server on %q", *addr)

		go func() {
			if err := fasthttp.ListenAndServe(*addr, httpRouter.Handler); err != nil {
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
			if err := fasthttp.Serve(lnTLS, tlsRouter.Handler); err != nil {
				panic(err)
			}
		}()
	}

	log.Printf("Serving files from directory %q", *docRoot)
	log.Printf("See stats at http://%s/stats", *addr)
	// Wait forever.
	select {}
}

func certmagicFastHTTPHandler(ctx *fasthttp.RequestCtx) {
	log.Printf("certmagicFastHTTPHandler: (%s) %s%s\n", ctx.Request.URI().String(), *docRoot, ctx.Path())
	fmt.Fprintf(ctx, "certmagicFastHTTPHandler: (%s) %s%s\n", ctx.Request.URI().String(), *docRoot, ctx.Path())
}

// repeatedly replace until nothing changed
func loopReplaceAll(s, old, new string) string {
	pre := s
	for {
		s = strings.ReplaceAll(s, old, new)
		if pre == s {
			return s
		}
		pre = s
	}
}

// check is the s include only number and . (check ipv4 address)
func isAllDotNumber(s string) bool {
	for i := len(s) - 1; i >= 0; i-- {
		// 0 - 9 and .
		if (s[i] > 57 || s[i] < 48) && s[i] != '.' {
			return false
		}
	}
	return true
}

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
