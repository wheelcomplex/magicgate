module github.com/wheelcomplex/magicgate/certmagic

go 1.14

replace github.com/mholt/acmez v0.1.1 => /home/david/home/wheelcomplex/magicgate/acmez
replace github.com/libdns/libdns v0.1.0 => /home/david/home/wheelcomplex/magicgate/libdns

require (
	github.com/klauspost/cpuid v1.2.5
	github.com/libdns/libdns v0.1.0
	github.com/mholt/acmez v0.1.1
	github.com/miekg/dns v1.1.30
	github.com/valyala/fasthttp v1.16.0
	go.uber.org/zap v1.16.0
	golang.org/x/crypto v0.0.0-20200728195943-123391ffb6de
)
