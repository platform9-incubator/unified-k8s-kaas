package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"log"
	"net/url"
	"strings"

	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"

	"github.com/smallfish/simpleyaml"
)

const (
	//AzureConfig Location of external cluster kubeconfig
	AzureConfig = "./config"
	//ProxyClientCert Location of crt file used by proxy
	//while talking to shadow API server. Signing CA should
	//be added to API requestheader-client-ca-file
	ProxyClientCert = "./certs/proxy/pki/issued/proxy.crt"
	//ProxyServerCert Location of crt file used by proxy
	//server while talking to client. Reusing the same crt
	ProxyServerCert = "./certs/proxy/pki/issued/proxy.crt"
	//ProxyServerKey Location of proxy server key
	ProxyServerKey = "./certs/proxy/pki/private/proxy.key"
	//ProxyClientKey Location of proxy client key
	ProxyClientKey = "./certs/proxy/pki/private/proxy.key"
	//APIServerCACert CA used to sign API server cert.
	//This must be trusted by proxy server
	APIServerCACert = "./certs/apiserver/pki/ca.crt"
)

//ParsedYaml holds contents of a parsed yaml
type ParsedYaml struct {
	Transport *http.Transport
	Host      string
	Token     string
}

func parseConfig() *ParsedYaml {
	parsed := ParsedYaml{}

	source, err := ioutil.ReadFile(AzureConfig)
	if err != nil {
		panic(err)
	}
	yaml, err := simpleyaml.NewYaml(source)
	if err != nil {
		panic(err)
	}
	//Get cluster details
	cluster := yaml.Get("clusters").GetIndex(0).Get("cluster")
	ca, err := cluster.Get("certificate-authority-data").String()
	server, err := cluster.Get("server").String()
	u, err := url.Parse(server)

	//get user details
	user := yaml.Get("users").GetIndex(0).Get("user")
	clienCert, err := user.Get("client-certificate-data").String()
	clienKey, err := user.Get("client-key-data").String()
	userToken, err := user.Get("token").String()

	//create TLS config
	decodedCert, err := base64.StdEncoding.DecodeString(clienCert)
	err = ioutil.WriteFile("/tmp/cert", decodedCert, 0644)
	decodedKey, err := base64.StdEncoding.DecodeString(clienKey)
	err = ioutil.WriteFile("/tmp/key", decodedKey, 0644)
	// Load client cert
	cert, err := tls.LoadX509KeyPair("/tmp/cert", "/tmp/key")
	// Load CA cert
	caCert, err := base64.StdEncoding.DecodeString(ca)
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
	}
	parsed.Transport = &http.Transport{TLSClientConfig: tlsConfig}
	parsed.Token = userToken
	parsed.Host = u.Host
	return &parsed
}

func getRemoteProxy() *httputil.ReverseProxy {
	parsed := parseConfig()
	directToRemote := func(req *http.Request) {
		req.URL.Scheme = "https"
		req.URL.Host = parsed.Host
		req.Header.Set("Authorization", parsed.Token)
	}
	proxy := &httputil.ReverseProxy{Director: directToRemote}
	proxy.Transport = parsed.Transport
	return proxy
}

func getLocalProxy() *httputil.ReverseProxy {
	cert, _ := tls.LoadX509KeyPair(ProxyClientCert, ProxyClientKey)
	caCert, _ := ioutil.ReadFile(APIServerCACert)
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
	}

	directToLocal := func(req *http.Request) {
		req.URL.Scheme = "https"
		req.URL.Host = "127.0.0.1:6443"
		cert := req.TLS.PeerCertificates[0]
		fmt.Printf("%d\n", len(cert.DNSNames))
		req.Header.Add("X-Remote-User", cert.Subject.CommonName)
		for _, orgName := range cert.Subject.Organization {
			req.Header.Add("X-Remote-Group", orgName)
		}

	}
	proxy := &httputil.ReverseProxy{Director: directToLocal}
	proxy.Transport = &http.Transport{TLSClientConfig: tlsConfig}
	return proxy
}

func main() {
	proxyLocal := getLocalProxy()
	proxyRemote := getRemoteProxy()

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "rbac") || strings.Contains(r.URL.Path, "certificates") || strings.Contains(r.URL.Path, "auth") {
			proxyLocal.ServeHTTP(w, r)
		} else {
			recW := httptest.NewRecorder()
			proxyLocal.ServeHTTP(recW, r)
			res := recW.Result()
			fmt.Println(res.StatusCode)
			if res.StatusCode != 403 {
				proxyRemote.ServeHTTP(w, r)
			} else {
				// headers
				for name, values := range recW.HeaderMap {
					w.Header()[name] = values
				}
				w.WriteHeader(res.StatusCode)
				w.Write(recW.Body.Bytes())
			}
		}
	})
	server := &http.Server{
		Addr: "127.0.0.1:8080",
		TLSConfig: &tls.Config{
			ClientAuth: tls.RequestClientCert,
		},
	}
	//should accept any client cert?
	log.Fatal(server.ListenAndServeTLS(ProxyServerCert, ProxyServerKey))
}
