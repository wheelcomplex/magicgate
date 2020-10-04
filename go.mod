module magicgate

go 1.16

// go mod edit -replace github.com/pselle/bar=/Users/pselle/Projects/bar

replace github.com/caddyserver/certmagic => /home/david/home/wheelcomplex/certmagic

replace github.com/wheelcomplex/certmagic => /home/david/home/wheelcomplex/certmagic

require (
	github.com/fasthttp/router v1.3.2
	github.com/valyala/fasthttp v1.16.0
	github.com/wheelcomplex/certmagic v0.0.0-00010101000000-000000000000
	golang.org/x/crypto v0.0.0-20201002170205-7f63de1d35b0
)
