package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"

	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"

	"github.com/gin-gonic/gin"

	"github.com/smallfish/simpleyaml"
)

const (
	//RemoteConfig Location of external cluster kubeconfig
	RemoteConfig = "./config"
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
	//ClientCACert that must be trusted by proxy server
	ClientCACert = "./certs/client/pki/ca.crt"
)

var proxyRemote *httputil.ReverseProxy

//ParsedYaml holds contents of a parsed yaml
type ParsedYaml struct {
	Transport *http.Transport
	Host      string
	Token     string
}

//Returns TLS Config given file locations for
//cert, key and data for caCert
func getTLSConfigFromData(certFile, keyFile, caCert []byte) *tls.Config {
	cert, _ := tls.X509KeyPair(certFile, keyFile)
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
	}
	return tlsConfig
}

func getTLSConfigFromFiles(certFile, keyFile, caCert string) *tls.Config {
	cert, _ := ioutil.ReadFile(certFile)
	key, _ := ioutil.ReadFile(keyFile)
	ca, _ := ioutil.ReadFile(caCert)
	return getTLSConfigFromData(cert, key, ca)
}

func parseConfig(configLocation string) *ParsedYaml {
	parsed := ParsedYaml{}

	source, err := ioutil.ReadFile(configLocation)
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
	cert, err := base64.StdEncoding.DecodeString(clienCert)
	key, err := base64.StdEncoding.DecodeString(clienKey)
	caCert, err := base64.StdEncoding.DecodeString(ca)

	parsed.Transport = &http.Transport{TLSClientConfig: getTLSConfigFromData(cert, key, caCert)}
	parsed.Token = userToken
	parsed.Host = u.Host
	return &parsed
}

func getRemoteProxy(configLocation string) *httputil.ReverseProxy {
	parsed := parseConfig(configLocation)
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
	proxy.Transport = &http.Transport{TLSClientConfig: getTLSConfigFromFiles(ProxyClientCert, ProxyClientKey, APIServerCACert)}
	return proxy
}
func selectClusterConfig(c *gin.Context) {
	fileName := c.Param("name")
	dir, _ := os.Getwd()
	fmt.Printf("Checking if file %s exists", dir+"/"+fileName)
	if _, err := os.Stat(dir + "/" + fileName); os.IsNotExist(err) {
		c.String(http.StatusBadRequest, fmt.Sprintf("Invalid cluster name: %s", fileName))
	}
	proxyRemote = getRemoteProxy(fileName)

}
func addClusterConfig(c *gin.Context) {
	// Source
	file, err := c.FormFile("file")
	if err != nil {
		c.String(http.StatusBadRequest, fmt.Sprintf("get form err: %s", err.Error()))
		return
	}
	if err := c.SaveUploadedFile(file, file.Filename); err != nil {
		c.String(http.StatusBadRequest, fmt.Sprintf("upload file err: %s", err.Error()))
		return
	}
	proxyRemote = getRemoteProxy(file.Filename)
	c.String(http.StatusOK, fmt.Sprintf("File %s uploaded successfully, remote cluster set", file.Filename))

}
func main() {

	proxyLocal := getLocalProxy()

	allRequestHandler := func(c *gin.Context) {
		if proxyRemote == nil {
			c.String(http.StatusBadRequest, fmt.Sprintf("No cluster set"))
		}
		r := c.Request
		w := c.Writer
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
	}

	caCert, _ := ioutil.ReadFile(ClientCACert)
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	r := gin.Default()
	server := &http.Server{
		Addr: "0.0.0.0:8080",
		TLSConfig: &tls.Config{
			//Force client certificate validation,
			//Required also to get PeerCertificates needed later to extract client identity information
			ClientAuth: tls.RequireAndVerifyClientCert,
			//Similar to setting client-ca for shadow API server.
			//Allows only certs signed by this CA
			ClientCAs: caCertPool,
		},
		Handler: r,
	}
	r.NoRoute(allRequestHandler)

	r.POST("/clusterconfig", addClusterConfig)
	r.PUT("/clusterconfig/:name", selectClusterConfig)

	log.Fatal(server.ListenAndServeTLS(ProxyServerCert, ProxyServerKey))
}
