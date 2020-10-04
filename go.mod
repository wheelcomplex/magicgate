module magicgate

go 1.16

// go mod edit -replace github.com/pselle/bar=/Users/pselle/Projects/bar

replace github.com/caddyserver/certmagic => /home/david/home/wheelcomplex/certmagic

replace github.com/wheelcomplex/certmagic => /home/david/home/wheelcomplex/certmagic

require (
	github.com/klauspost/cpuid v1.3.1 // indirect
	github.com/miekg/dns v1.1.31 // indirect
	github.com/valyala/fasthttp v1.16.0
	github.com/wheelcomplex/certmagic v0.12.0
	github.com/wheelcomplex/fasthttprouter v0.1.1
	go.uber.org/multierr v1.6.0 // indirect
	go.uber.org/zap v1.16.0
	golang.org/x/crypto v0.0.0-20201002170205-7f63de1d35b0
	golang.org/x/net v0.0.0-20201002202402-0a1ea396d57c // indirect
	golang.org/x/text v0.3.3 // indirect
)
