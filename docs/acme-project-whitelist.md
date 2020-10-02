# Whitelist for Project 1 (ACME)
For this project, you may only use languages and packages listed in this document. Using something not listed here will be considered fraud. Depending on the severity of the fraud, we will either give you a 1 for this project, or make an official report following the ["Disziplinarordnung"](https://www.admin.ch/opc/de/classified-compilation/20042642/index.html). For extensions of this list, please open a [Gitlab issue](https://gitlab.inf.ethz.ch/PRV-PERRIG/netsec-course/netsec-2020-issues).

## Python 3
You may use the standard library, as specified in https://docs.python.org/3/library/index.html.

Additionaly, you may import the following:
- cryptography
- dnslib
- Flask
- requests
- PyCryptodome
- Django
- dacite


## Golang
You may use the standard library. Note that not all packages that are part of the Go Project are part of the standard library! See https://golang.org/pkg/ for more info.

Additionaly, you may import the following:
- https://github.com/sirupsen/logrus
- https://github.com/miekg/dns
- https://github.com/jessevdk/go-flags
- https://github.com/x-cray/logrus-prefixed-formatter


##  Java 13
You may use the standard library, as specified in
https://docs.oracle.com/en/java/javase/13/docs/api/index.html

Maven and Gradle are installed.

Additionaly, you may import the following:
- com.sun.net.httpserver
- dnsjava (https://mvnrepository.com/artifact/dnsjava/dnsjava)
- JSON-P (https://javaee.github.io/jsonp/)
- Bouncy Castle Crypto APIs (https://www.bouncycastle.org/java.html)
- nanohttpd (https://mvnrepository.com/artifact/org.nanohttpd/nanohttpd/2.3.1)


## Rust
You may use the standard library as specified in
https://doc.rust-lang.org/std/

Cargo is installed

Additionaly, you may use the following crates:
- reqwest
- openssl
- getopts
- base64
- hyper
- serde
- serde_json
- trust-dns-server
- rust-crypto
- futures
- tokio
- gotham
- tokio-rustls

## C
A standard GCC installation is available on the CI containers. Moreover, you may use the following libraries:

- libssl
- libcrypto
- libtls
- libutil
- libbsd
- libcurl
- json-c
- libc
- libm
- b64.c

The bison tool for parser generation is installed as well.
