package main

import (
	"net/http"
	"time"
)

type ParsedYaml struct {
	Transport *http.Transport
	Host      string
	Token     string
}

type AdmissionReview struct {
	Response *AdmissionResponse
}

// AdmissionResponse describes an admission response.
type AdmissionResponse struct {
	// Allowed indicates whether or not the admission request was permitted.
	//You have to hack when you have to hack
	Allowed bool
}
type UserInfo struct {
	Name  string `json:"name"`
	Group string `json:"group"`
}

type AdmissionObject struct {
	Kind       string `yaml:"kind"`
	APIVersion string `yaml:"apiVersion"`
	Request    struct {
		UID  string `yaml:"uid"`
		Kind struct {
			Group   string `yaml:"group"`
			Version string `yaml:"version"`
			Kind    string `yaml:"kind"`
		} `yaml:"kind"`
		Resource struct {
			Group    string `yaml:"group"`
			Version  string `yaml:"version"`
			Resource string `yaml:"resource"`
		} `yaml:"resource"`
		Name      string `yaml:"name"`
		Namespace string `yaml:"namespace"`
		Operation string `yaml:"operation"`
		UserInfo  struct {
			Username string   `yaml:"username"`
			UID      string   `yaml:"uid"`
			Groups   []string `yaml:"groups"`
		} `yaml:"userInfo"`
		Object struct {
			Metadata struct {
				Name              string    `yaml:"name"`
				Namespace         string    `yaml:"namespace"`
				SelfLink          string    `yaml:"selfLink"`
				UID               string    `yaml:"uid"`
				ResourceVersion   int       `yaml:"resourceVersion"`
				CreationTimestamp time.Time `yaml:"creationTimestamp"`
				Annotations       struct {
					ControlPlaneAlphaKubernetesIoLeader time.Time `yaml:"control-plane.alpha.kubernetes.io/leader"`
				} `yaml:"annotations"`
			} `yaml:"metadata"`
			Subsets interface{} `yaml:"subsets"`
		} `yaml:"object"`
		OldObject struct {
			Metadata struct {
				Name              string    `yaml:"name"`
				Namespace         string    `yaml:"namespace"`
				UID               string    `yaml:"uid"`
				ResourceVersion   int       `yaml:"resourceVersion"`
				CreationTimestamp time.Time `yaml:"creationTimestamp"`
				Annotations       struct {
					ControlPlaneAlphaKubernetesIoLeader time.Time `yaml:"control-plane.alpha.
kubernetes.io/leader"`
				} `yaml:"annotations"`
			} `yaml:"metadata"`
			Subsets interface{} `yaml:"subsets"`
		} `yaml:"oldObject"`
	} `yaml:"request"`
}

type AccessReviewResponse struct {
	Kind       string `yaml:"kind"`
	APIVersion string `yaml:"apiVersion"`
	Metadata   struct {
		CreationTimestamp interface{} `yaml:"creationTimestamp"`
	} `yaml:"metadata"`
	Spec struct {
		ResourceAttributes struct {
			Namespace string `yaml:"namespace"`
			Verb      string `yaml:"verb"`
			Name      string `yaml:"name"`
		} `yaml:"resourceAttributes"`
	} `yaml:"spec"`
	Status struct {
		Allowed bool `yaml:"allowed"`
	} `yaml:"status"`
}

type SelfSubjectAccessReview struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
}
