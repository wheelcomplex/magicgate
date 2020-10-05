module magicgate

go 1.16

// go mod edit -replace github.com/pselle/bar=/Users/pselle/Projects/bar

// replace github.com/caddyserver/certmagic => /home/david/home/wheelcomplex/certmagic

// replace github.com/caddyserver/certmagic v0.12.0 => github.com/wheelcomplex/certmagic v0.12.0

// replace github.com/wheelcomplex/certmagic => /home/david/home/wheelcomplex/certmagic

// replace github.com/valyala/fasthttp v1.16.0 => github.com/wheelcomplex/fasthttp 0.0.0-20201004003347-689f81a0c599

replace github.com/valyala/fasthttp v1.16.0 => /home/david/home/wheelcomplex/fasthttp

require (
	github.com/buaazp/fasthttprouter v0.1.1
	github.com/caddyserver/certmagic v0.12.0
	github.com/valyala/fasthttp v1.16.0
	go.uber.org/zap v1.16.0
	golang.org/x/crypto v0.0.0-20201002170205-7f63de1d35b0
)
