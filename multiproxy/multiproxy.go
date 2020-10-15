// multiproxy is a package for create tcp/udp proxy,
// from https://github.com/arkadijs/goproxy

package multiproxy

import (
	"io"
	"log"
	"net"
	"strings"
	"time"

	"github.com/wheelcomplex/lumberjack"
	"github.com/wheelcomplex/magicgate/utils"
)

var zeroTCPAddr = &net.TCPAddr{
	IP: net.IPv4zero,
}

var zeroUDPAddr = &net.UDPAddr{
	IP: net.IPv4zero,
}

// ProxyCtx contains incoming request and manages outgoing response.
type ProxyCtx struct {
	Err      error
	AuthOK   bool
	AuthInfo string

	proxyKey string
	proto    string

	fe *forwardEntry

	sessID       uint64 // session id
	linkProtocol string
	appProtocol  string

	frontConn net.Conn
	backConn  net.Conn
}

// LocalAddr returns local address for the given request.
//
// Always returns non-nil result.
func (ctx *ProxyCtx) LocalAddr() net.Addr {
	return nil
}

// RemoteAddr returns client address for the given request.
//
// Always returns non-nil result.
func (ctx *ProxyCtx) RemoteAddr() net.Addr {
	return nil
}

// SessionInfo returns session information for the given request.
//
// Always returns non-nil result.
func (ctx *ProxyCtx) SessionInfo() string {
	return "SessionInfo"
}

// ProtocolInfo returns protocol information for the given request.
//
// Always returns non-nil result.
func (ctx *ProxyCtx) ProtocolInfo() string {
	return "ProtocolInfo"
}

// ProxyHandler is a function to handle proxy connections
type ProxyHandler func(ctx *ProxyCtx)

// ProxyAuthHandler is a function to handle proxy auth,
// return nil for auth ok, or error message
type ProxyAuthHandler func(ctx *ProxyCtx) error

// ProxyConfig for setup proxy server
type ProxyConfig struct {
	Forwards          map[string]string // map[link-protocol(tcp/udp)/<frontend addr>]<backend addr|passive,...>
	KeepaliveInterval time.Duration
	KeepaliveTimeout  time.Duration
	SynTimeout        time.Duration
	Coolingtimeout    time.Duration

	LogWriter   *lumberjack.Logger
	AuthHandler ProxyAuthHandler
}

// NewListConfig return a *ProxyConfig with initial settings,
// list should has format: <protocol>/<front address>/backend addr,...+another frontend,
// word "passive" as backend means backend connection initial from peer,
// example: tcp/0.0.0.0:80/10.0.0.2:8080,10.0.0.3:9080+udp/0.0.0.0:53/10.0.0.2:5353,passive
func NewListConfig(list string, authHandler ProxyAuthHandler, logWriter *lumberjack.Logger) *ProxyConfig {
	if len(list) == 0 {
		return nil
	}
	if logWriter != nil {
		log.SetOutput(logWriter)
	}
	//
	forwards := make(map[string]string)

	//
	list = strings.ToLower(utils.LoopReplaceAll(list, " ", "+"))

	// front split
	listArr := strings.Split(list, "+")
	for _, line := range listArr {
		if line == "" {
			continue
		}
		frontArr := strings.Split(line, "/")
		if len(frontArr) < 3 {
			log.Printf("invalid proxy config(proto/front/back): %s\n", line)
			continue
		}
		proto := frontArr[0]
		front := frontArr[1]
		back := frontArr[2]
		if proto != "tcp" && proto != "udp" {
			log.Printf("invalid proxy protocol(tcp|udp): %s\n", proto)
			continue
		}
		var err error
		_, _, err = net.SplitHostPort(front)
		if err != nil {
			log.Printf("invalid proxy frontend(host:port): %s\n", err)
			continue
		}
		// backend is allowed to be empty

		forwards[proto+"/"+front] = back
	}

	return NewForwardConfig(forwards, authHandler, logWriter)
}

// NewForwardConfig return a *ProxyConfig with initial settings
func NewForwardConfig(forwards map[string]string, authHandler ProxyAuthHandler, logWriter *lumberjack.Logger) *ProxyConfig {
	cfg := NewDefaultConfig()
	cfg.LogWriter = logWriter
	cfg.AuthHandler = authHandler
	if logWriter != nil {
		log.SetOutput(logWriter)
	}
	// copy
	for k := range forwards {
		cfg.Forwards[k] = forwards[k]
	}
	return cfg
}

// NewDefaultConfig return a *ProxyConfig with initial settings
func NewDefaultConfig() *ProxyConfig {
	cfg := &ProxyConfig{
		KeepaliveInterval: 30 * time.Second,
		KeepaliveTimeout:  1 * time.Second,
		SynTimeout:        800 * time.Millisecond,
		Coolingtimeout:    5 * time.Second,
		Forwards:          make(map[string]string),
		LogWriter:         nil,
		AuthHandler:       nil,
	}
	return cfg
}

// NewProxyServer return a ProxyServer base on input proxy list,
// list should has format: <protocol>/<front address>/backend addr,...,
// word "passive" as backend means backend connection initial from peer,
// example: tcp/0.0.0.0:80/10.0.0.2:8080,10.0.0.3:9080,
// example2: udp/0.0.0.0:53/10.0.0.2:5353,passive,
func NewProxyServer(list string, auth ProxyAuthHandler, logWriter *lumberjack.Logger) *ProxyServer {

	return NewProxyServerByConf(NewListConfig(list, auth, logWriter))

}

//
type forwardEntry struct {
	front       string // link protocol / front address
	proto       string // tcp|udp
	proxyKey    string
	frontAddr   net.Addr
	tcpListener *net.TCPListener
	udpConn     *net.UDPConn
	backends    map[string]net.Addr
	errorTTL    map[string]int64 // time.Now().Unix(), in second
}

// reset close all connections and release all resources
func (fe *forwardEntry) reset() {
	//
	return
}

func newForwardEntry(front, proto string, frontAddr net.Addr) *forwardEntry {
	return &forwardEntry{
		front:     front,
		proto:     proto,
		frontAddr: frontAddr,
		proxyKey:  proto + "/" + front,
		backends:  make(map[string]net.Addr),
		errorTTL:  make(map[string]int64),
	}
}

// ProxyServer represent a proxy server
type ProxyServer struct {
	cfg *ProxyConfig //

	proxyMap map[string]*forwardEntry // map[frontend address]<backend address|passive mode>

	sessions map[uint64]*ProxyCtx //

	authHandler ProxyAuthHandler
}

// NewProxyServerByConf return a ProxyServer base on input proxy list
func NewProxyServerByConf(cfg *ProxyConfig) *ProxyServer {
	if cfg == nil {
		log.Printf("nil proxy config: %v\n", cfg)
		return nil
	}
	ps := &ProxyServer{
		proxyMap:    make(map[string]*forwardEntry),
		sessions:    make(map[uint64]*ProxyCtx),
		cfg:         cfg,
		authHandler: cfg.AuthHandler,
	}
	// parse cfg.Forwards
	if err := ps.AddForwardMap(ps.cfg.Forwards); err != nil {
		log.Fatalf("invalid proxy config: %s\n", err)
		return nil
	}

	return ps
}

// AddForward create new forward tunnel and process income connections
func (ps *ProxyServer) AddForward(list string) error {
	cfg := NewListConfig(list, nil, nil)
	return ps.AddForwardMap(cfg.Forwards)
}

// AddForwardMap create new forward tunnel and process income connections
func (ps *ProxyServer) AddForwardMap(forward map[string]string) error {

	// udp/0.0.0.0:53/10.0.0.2:5353,passive
	for frontLine, backLine := range forward {
		frontLine = strings.ToLower(frontLine)
		backLine = strings.ToLower(backLine)

		frontArr := strings.Split(frontLine, "/")
		if len(frontArr) < 2 {
			log.Printf("invalid proxy config(proto/front): %s\n", frontLine)
			continue
		}
		proto := frontArr[0]
		front := frontArr[1]
		if proto != "tcp" && proto != "udp" {
			log.Printf("invalid proxy protocol(tcp|udp): %s <= %s\n", proto, frontLine)
			continue
		}
		host, port, err := net.SplitHostPort(front)
		if err != nil {
			log.Printf("invalid proxy frontend address(host:port): %s, %s <= %s\n", err, front, frontLine)
			continue
		}
		front = host + ":" + port
		proxykey := proto + "/" + front
		var frontAddr net.Addr
		if proto == "tcp" {
			frontAddr, err = net.ResolveTCPAddr("tcp", front)
		} else {
			frontAddr, err = net.ResolveUDPAddr("udp", front)
		}
		if err != nil {
			log.Printf("unable to resolve proxy frontend address(host:port): %s, %s <= %s\n", err, front, frontLine)
			continue
		}

		ps.proxyMap[proxykey] = newForwardEntry(front, proto, frontAddr)

		// parse backends

		backArr := strings.Split(backLine, ",")
		for _, back := range backArr {
			if back == "passive" {
				// backends will be register later
				continue
			}
			host, port, err = net.SplitHostPort(back)
			if err != nil {
				log.Printf("invalid proxy backend address(host:port): %s, %s <= %s\n", err, back, backLine)
				continue
			}
			back = host + ":" + port
			var backAddr net.Addr
			if proto == "tcp" {
				backAddr, err = net.ResolveTCPAddr("tcp", back)
			} else {
				backAddr, err = net.ResolveUDPAddr("udp", back)
			}
			if err != nil {
				log.Printf("unable to resolve proxy backend address(host:port): %s, %s <= %s\n", err, back, backLine)
				continue
			}
			ps.proxyMap[proxykey].backends[back] = backAddr
			ps.proxyMap[proxykey].errorTTL[back] = 0
		}
	}
	return nil
}

// DelForward delete forward tunnel
func (ps *ProxyServer) DelForward(list string) error {
	cfg := NewListConfig(list, nil, nil)
	return ps.DelForwardMap(cfg.Forwards)
}

// DelForwardMap create new forward tunnel and process income connections
func (ps *ProxyServer) DelForwardMap(forward map[string]string) error {

	// udp/0.0.0.0:53/10.0.0.2:5353,passive
	for frontLine := range forward {
		frontLine = strings.ToLower(frontLine)

		frontArr := strings.Split(frontLine, "/")
		if len(frontArr) < 2 {
			log.Printf("invalid proxy config(proto/front): %s\n", frontLine)
			continue
		}
		proto := frontArr[0]
		front := frontArr[1]
		if proto != "tcp" && proto != "udp" {
			log.Printf("invalid proxy protocol(tcp|udp): %s <= %s\n", proto, frontLine)
			continue
		}
		host, port, err := net.SplitHostPort(front)
		if err != nil {
			log.Printf("invalid proxy frontend address(host:port): %s, %s <= %s\n", err, front, frontLine)
			continue
		}
		front = host + ":" + port
		proxykey := proto + "/" + front

		if fe, ok := ps.proxyMap[proxykey]; ok {
			delete(ps.proxyMap, proxykey)
			fe.reset()
		}
	}
	return nil
}

// ForwardInfo return forward info in map
func (ps *ProxyServer) ForwardInfo() map[string]string {

	forwards := make(map[string]string)

	for k := range ps.cfg.Forwards {
		forwards[k] = ps.cfg.Forwards[k]
	}

	return forwards
}

// netIoCopy do io.Copy between backConn, frontConn,
// return latest err
func (ps *ProxyServer) netIoCopy(proxyKey string, keepFront bool, frontConn, backConn net.Conn) (err error) {

	// Todo: make it works on UDP
	// send to backend is ok, but read from backend and write to frontend:write udp [::]:53: write: destination address required; 0 bytes forwarded

	frontErrChan := make(chan error, 1)
	backErrChan := make(chan error, 1)

	// Todo: identify which endpoint is in error
	go func(backConn, frontConn net.Conn) {
		w, err := io.Copy(frontConn, backConn)
		log.Printf("frontend connection closed: %v; %v bytes forwarded\n", err, w)
		log.Printf("copy to backend: %s, %s+%s -> %s+%s, %v, %v ...\n", proxyKey, frontConn.LocalAddr(), frontConn.RemoteAddr(), backConn.LocalAddr(), backConn.RemoteAddr(), w, err)
		frontErrChan <- err
	}(backConn, frontConn)
	go func(backConn, frontConn net.Conn) {
		w, err := io.Copy(backConn, frontConn)
		log.Printf("backend connection closed: %v; %v bytes forwarded\n", err, w)
		log.Printf("copy to frontend: %s, %s+%s -> %s+%s, %v, %v ...\n", proxyKey, backConn.LocalAddr(), backConn.RemoteAddr(), frontConn.LocalAddr(), frontConn.RemoteAddr(), w, err)
		backErrChan <- err
	}(backConn, frontConn)

	// exit until both connections closed
	select {
	case err = <-frontErrChan:
		log.Printf("frontend connection error: %s,  closing backend, %s -> %s, %s ...\n", proxyKey, frontConn.LocalAddr(), frontConn.RemoteAddr(), err)
		time.Sleep(2 * ps.cfg.SynTimeout)
		if !keepFront {
			frontConn.Close()
		}
		backConn.Close()
		err = <-backErrChan
		log.Printf("backend connection error: %s, closing %s -> %s, %s ...\n", proxyKey, backConn.LocalAddr(), backConn.RemoteAddr(), err)
	case err = <-backErrChan:
		log.Printf("backend connection error: %s, closing frontend, %s -> %s, %s ...\n", proxyKey, backConn.LocalAddr(), backConn.RemoteAddr(), err)
		time.Sleep(2 * ps.cfg.SynTimeout)
		backConn.Close()
		if !keepFront {
			frontConn.Close()
		}
		err = <-frontErrChan
		log.Printf("frontend connection error: %s, closing %s -> %s, %s ...\n", proxyKey, frontConn.LocalAddr(), frontConn.RemoteAddr(), err)
	}
	return err
}

// tcpServer run a tcp proxy server,
func (ps *ProxyServer) tcpServer(proxyKey string) {
	log.Printf("tcp proxying for %s ...\n", proxyKey)
	entry := ps.proxyMap[proxyKey]
	var alive, allcooling, nonbackend bool
	for {
		frontConn, err := entry.tcpListener.AcceptTCP()
		if err != nil {
			log.Printf("failed to accept connection from %s: %v\n", proxyKey, err)
			time.Sleep(500 * time.Millisecond)
		} else {
			log.Printf("new connection: %s: %s <- %s\n", proxyKey, frontConn.LocalAddr(), frontConn.RemoteAddr())
			if len(ps.proxyMap[proxyKey].backends) == 0 {
				if !nonbackend {
					log.Printf("all backends removed, %s, closing frontend %s <- %s ...\n", proxyKey, frontConn.LocalAddr(), frontConn.RemoteAddr())
					nonbackend = true
				}
				frontConn.Close()
				continue
			}
			nonbackend = false

			alive = false
			for addrKey := range ps.proxyMap[proxyKey].backends {
				if time.Now().Unix() > ps.proxyMap[proxyKey].errorTTL[addrKey] {
					alive = true
					break
				}
			}

			if !alive {
				if !allcooling {
					log.Printf("all backends cooling, %s, closing frontend %s <- %s ...\n", proxyKey, frontConn.LocalAddr(), frontConn.RemoteAddr())
					allcooling = true
				}
				frontConn.Close()
				continue
			}
			allcooling = false

			go func(frontConn *net.TCPConn) {
				// copy frontConn
				ps.tcpBackend(proxyKey, frontConn)
			}(frontConn)
		}
	}
}

// tcpBackend connect to backend and do io.Copy,
func (ps *ProxyServer) tcpBackend(proxyKey string, frontConn *net.TCPConn) {
	entry := ps.proxyMap[proxyKey]
	var backConn *net.TCPConn
	var tmpConn net.Conn
	var err error

	log.Printf("tcp backend for %s, front %s+%s ...\n", proxyKey, frontConn.LocalAddr(), frontConn.RemoteAddr())

	for {
		// look for a backend and try to connect

		backConn = nil
		var addrKey string
		var backAddr net.Addr
		for addrKey, backAddr = range entry.backends {
			if time.Now().Unix() < entry.errorTTL[addrKey] {
				continue
			}
			log.Printf("connecting to backend: %s, %s/%d ...\n", proxyKey, backAddr.String(), ps.cfg.SynTimeout)
			tmpConn, err = net.DialTimeout("tcp", backAddr.String(), ps.cfg.SynTimeout)
			if err != nil {
				log.Printf("connect to backend: %s, %s/%s ...\n", proxyKey, backAddr.String(), err)
				entry.errorTTL[addrKey] = time.Now().Unix() + int64(ps.cfg.Coolingtimeout)
				continue
			}
			backConn = tmpConn.(*net.TCPConn)
			log.Printf("connected to backend:  %s, %s, local %s -> remote %s ...\n", proxyKey, backAddr.String(), backConn.LocalAddr(), backConn.RemoteAddr())
			break
		}

		if backConn == nil {
			log.Printf("all backends cooling, %s, closing frontend %s <- %s ...\n", proxyKey, frontConn.LocalAddr(), frontConn.RemoteAddr())
			frontConn.Close()
			return
		}

		ps.netIoCopy(proxyKey, false, frontConn, backConn)
		return
	}
}

// udpBackend connect to backend and do io.Copy,
func (ps *ProxyServer) udpBackend(proxyKey string, frontConn *net.UDPConn) {
	entry := ps.proxyMap[proxyKey]
	var backConn *net.UDPConn
	var tmpConn net.Conn
	var err error

	var allCooling bool
	log.Printf("udp backend for %s, front %s+%s ...\n", proxyKey, frontConn.LocalAddr(), frontConn.RemoteAddr())
	for {
		// look for a backend and try to connect

		backConn = nil
		var addrKey string
		var backAddr net.Addr
		for addrKey, backAddr = range entry.backends {
			if time.Now().Unix() < entry.errorTTL[addrKey] {
				if !allCooling {
					log.Printf("backend is cooling: %s, %s/%d/%d\n", proxyKey, backAddr.String(), entry.errorTTL[addrKey]-time.Now().Unix(), ps.cfg.Coolingtimeout)
				}
				continue
			}
			log.Printf("connecting to backend: %s, %s/%d ...\n", proxyKey, backAddr.String(), ps.cfg.SynTimeout)
			tmpConn, err = net.DialTimeout("udp", backAddr.String(), ps.cfg.SynTimeout)
			if err != nil {
				log.Printf("connect to backend: %s, %s/%s ...\n", proxyKey, backAddr.String(), err)
				entry.errorTTL[addrKey] = time.Now().Unix() + int64(ps.cfg.Coolingtimeout)
				continue
			}
			allCooling = false
			backConn = tmpConn.(*net.UDPConn)
			log.Printf("connected to backend: %s, %s, local %s -> remote %s ...\n", proxyKey, backAddr.String(), backConn.LocalAddr(), backConn.RemoteAddr())
			break
		}

		if len(entry.backends) == 0 {
			if !allCooling {
				log.Printf("all backends removed, %s, waiting %d ...\n", proxyKey, ps.cfg.Coolingtimeout)
				allCooling = true
			}
			time.Sleep(5 * ps.cfg.Coolingtimeout)
			continue
		}

		if backConn == nil {
			if !allCooling {
				log.Printf("all backends cooling, %s, waiting %d ...\n", proxyKey, ps.cfg.Coolingtimeout)
				allCooling = true
			}
			time.Sleep(ps.cfg.Coolingtimeout)
			continue
		}

		ps.netIoCopy(proxyKey, true, frontConn, backConn)
		// continue for next connect
	}
}

// StartProxy create listen sockets and process income connections,
func (ps *ProxyServer) StartProxy() {

	var err error

	if ps.cfg.LogWriter != nil {
		log.SetOutput(ps.cfg.LogWriter)
	}

	// launch listener
	for proxyKey, entry := range ps.proxyMap {
		if entry.proto == "udp" {

			// udp should listen on all local ip

			// ifaces, err := net.Interfaces()
			// // handle err
			// for _, i := range ifaces {
			// 	addrs, err := i.Addrs()
			// 	// handle err
			// 	for _, addr := range addrs {
			// 		var ip net.IP
			// 		switch v := addr.(type) {
			// 		case *net.IPNet:
			// 			ip = v.IP
			// 		case *net.IPAddr:
			// 			ip = v.IP
			// 		}
			// 		// process IP address
			// 	}
			// }

			ps.proxyMap[proxyKey].udpConn, err = net.ListenUDP("udp", entry.frontAddr.(*net.UDPAddr))
			if err != nil {
				log.Fatalf("Failed to setup UDP listener on `%s`: %v\n", entry.frontAddr, err)
			}
			//
			go func(proxyKey string) {
				// copy proxyKey
				ps.udpBackend(proxyKey, ps.proxyMap[proxyKey].udpConn)
			}(proxyKey)
		} else {
			ps.proxyMap[proxyKey].tcpListener, err = net.ListenTCP("tcp", entry.frontAddr.(*net.TCPAddr))
			if err != nil {
				log.Fatalf("Failed to setup TCP listener on `%s`: %v\n", entry.frontAddr, err)
			}
			//
			go func(proxyKey string) {
				// copy proxyKey
				ps.tcpServer(proxyKey)
			}(proxyKey)
		}
		// let go routine has a gap to run
		time.Sleep(100 * time.Millisecond)

		// log.Printf("listening %s://%s ...\n", entry.proto, entry.frontAddr)
	}

}
