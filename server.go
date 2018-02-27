package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"os"
	"os/exec"
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
var proxyLocal *httputil.ReverseProxy
var server *http.Server

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
		if len(req.TLS.PeerCertificates) > 0 {
			cert := req.TLS.PeerCertificates[0]
			fmt.Printf("%d\n", len(cert.DNSNames))
			req.Header.Add("X-Remote-User", cert.Subject.CommonName)
			for _, orgName := range cert.Subject.Organization {
				req.Header.Add("X-Remote-Group", orgName)
			}
		} else {
			req.URL.Path = "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews"
			req.Method = "POST"
			accessCheckReq := `{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectAccessReview","metadata":
							  {"creationTimestamp":null},"spec":{"resourceAttributes":{"group":"GROUP",
							"name":"NAME","namespace":"SPACE","verb":"VERB"}}}`
			x, _ := ioutil.ReadAll(req.Body)
			f := AdmissionObject{}
			json.Unmarshal(x, &f)
			fmt.Println(f)
			req.Header.Add("X-Remote-User", f.Request.UserInfo.Username)
			for _, orgName := range f.Request.UserInfo.Groups {
				req.Header.Add("X-Remote-Group", orgName)
			}
			filledResGrp := strings.Replace(accessCheckReq, "GROUP", f.Request.Resource.Group, -1)
			filledResName := strings.Replace(filledResGrp, "NAME", f.Request.Resource.Resource, -1)
			filledResNamespace := strings.Replace(filledResName, "SPACE", f.Request.Namespace, -1)
			filledResVerb := strings.Replace(filledResNamespace, "VERB", f.Request.Operation, -1)

			req.Body = ioutil.NopCloser(strings.NewReader(filledResVerb))
			req.ContentLength = int64(len(filledResVerb))
		}
	}
	proxy := &httputil.ReverseProxy{Director: directToLocal}
	proxy.Transport = &http.Transport{TLSClientConfig: getTLSConfigFromFiles(ProxyClientCert, ProxyClientKey, APIServerCACert)}
	return proxy
}

func getAdmissionControllerProxy() *httputil.ReverseProxy {
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

func addmissionController(c *gin.Context) {
	recW := httptest.NewRecorder()
	proxyLocal.ServeHTTP(recW, c.Request)
	res := recW.Result()
	x, _ := ioutil.ReadAll(res.Body)
	f := AccessReviewResponse{}
	json.Unmarshal(x, &f)
	fmt.Println(f)
	admissionStatusResponse := AdmissionResponse{}
	status := AdmissionReview{}
	admissionStatusResponse.Allowed = f.Status.Allowed
	status.Response = &admissionStatusResponse
	fmt.Println("Admission review response, allowed = ", f.Status.Allowed)
	c.JSON(res.StatusCode, status)
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

func generateKubeConfig(c *gin.Context) {
	userInfo := UserInfo{}
	c.BindJSON(&userInfo)
	fmt.Print("Obtained this json ", userInfo)
	if userInfo.Group == "" {
		userInfo.Group = "nogroup"
	}
	dir, _ := os.Getwd()
	command := dir + "/easy-rsa/easyrsa3/easyrsa"

	genReq := exec.Command(command, "--batch", "--req-cn="+userInfo.Name, "--req-email=", "--dn-mode=org", "--req-org="+userInfo.Group, "gen-req", userInfo.Name, "nopass")
	fmt.Print("Command to be executed ", genReq)
	genReq.Dir = dir + "/certs/client"
	output, err := genReq.CombinedOutput()
	if err != nil {
		fmt.Print("Could not execute command ", err)
	}
	fmt.Print(string(output))
	signReq := exec.Command(command, "--batch", "sign-req", "client", userInfo.Name)
	fmt.Print("Command to be executed ", signReq)
	signReq.Dir = dir + "/certs/client"
	output, err = signReq.CombinedOutput()
	if err != nil {
		fmt.Print("Could not execute command ", err)
	}
	fmt.Print(string(output))

	caBytes, _ := ioutil.ReadFile("./certs/proxy/pki/ca.crt")
	clienCert, _ := ioutil.ReadFile("./certs/client/pki/issued/" + userInfo.Name + ".crt")
	clientKey, _ := ioutil.ReadFile("./certs/client/pki/private/" + userInfo.Name + ".key")

	config := `{"apiVersion":"v1","clusters":[{"cluster":{"certificate-authority-data":"CACERT",
		"server":"https://34.216.73.235:8080"},"name":"myK8sCluster"}],"contexts":
		[{"context":{"cluster":"myK8sCluster","user":"usera"},"name":"myK8sCluster"}],
		"current-context":"myK8sCluster","kind":"Config","preferences":{},"users":
		[{"name":"usera","user":{"client-certificate-data":"CLIENT_CERT","client-key-data":"CLIENT_KEY"}}]}`
	config1 := strings.Replace(config, "CACERT", base64.StdEncoding.EncodeToString(caBytes), -1)
	config2 := strings.Replace(config1, "CLIENT_CERT", base64.StdEncoding.EncodeToString(clienCert), -1)
	config3 := strings.Replace(config2, "CLIENT_KEY", base64.StdEncoding.EncodeToString(clientKey), -1)

	f, err := ioutil.TempFile("/tmp", "kubeconfig")
	f.WriteString(config3)
	f.Close()
	c.Header("Content-Description", "File Transfer")
	c.Header("Content-Transfer-Encoding", "binary")
	c.Header("Content-Disposition", "attachment; filename= kubeconfig.yml")
	c.Header("Content-Type", "application/octet-stream")

	c.File(f.Name())
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

	proxyLocal = getLocalProxy()

	allRequestHandler := func(c *gin.Context) {
		if proxyRemote == nil {
			c.String(http.StatusBadRequest, fmt.Sprintf("No cluster set"))
		}
		r := c.Request
		w := c.Writer
		fmt.Print("Got this request " + r.URL.Path)
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
	server = &http.Server{
		Addr: "0.0.0.0:8080",
		TLSConfig: &tls.Config{
			//Force client certificate validation,
			//Required also to get PeerCertificates needed later to extract client identity information
			//Ideally should be RequireAndVerifyClientCert, but webhooks are not using certs

			ClientAuth: tls.VerifyClientCertIfGiven,
			//Similar to setting client-ca for shadow API server.
			//Allows only certs signed by this CA
			ClientCAs: caCertPool,
		},
		Handler: r,
	}

	r.NoRoute(allRequestHandler)

	r.POST("/clusterconfig", addClusterConfig)
	r.PUT("/clusterconfig/:name", selectClusterConfig)
	r.POST("/kubeconfig", generateKubeConfig)
	r.Any("/access", addmissionController)

	log.Fatal(server.ListenAndServeTLS(ProxyServerCert, ProxyServerKey))
}
