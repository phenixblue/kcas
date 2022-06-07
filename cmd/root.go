/*
Copyright © 2022 T-Mobile, US Platform Engineering

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"twr.dev/kcas/pkg/kube"
)

const (
	POD_ENV     = "KCAS_POD_NAME"
	CLUSTER_ENV = "KCAS_CLUSTER_NAME"
)

var (
	cmClient         *cmConfig
	cfgFile          string
	cmName           string
	cmNamespace      string
	cmKey            string
	kubeconfig       string
	kubeContext      string
	defaultCertValue string
	cmOptions        metav1.ListOptions
)

type cmConfig struct {
	k8sInterface kubernetes.Interface
	mutex        *sync.Mutex
	caCert       string
}

type infoResponse struct {
	Pod            string    `json:"pod"`
	Cluster        string    `json:"cluster"`
	CaDaysToExpire int       `json:"ca-days"`
	Datetime       time.Time `json:"datetime"`
}

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "kcas",
	Short: "A utility to discover and serve the Kubernetes API Server CA Certificate to a target cluster",
	Long:  `A utility to discover and serve the Kubernetes API Server CA Certificate to a target cluster`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	Run: func(cmd *cobra.Command, args []string) {

		// Set default value for cert
		defaultCertValue = "No Cert available"

		// Setup the Kubernetes Client
		client, err := kube.CreateKubeClient(kubeconfig, kubeContext)
		if err != nil {
			message := fmt.Sprintf("ERROR: Unable to generate kubernetes client: %v\n", err)
			panic(message)
		}

		// Setup initial info
		cmClient = &cmConfig{}
		cmClient.k8sInterface = client
		cmClient.mutex = &sync.Mutex{}

		// Setup configmap watcher
		go watchConfigMap(cmClient)

		// Handel routes
		http.HandleFunc("/info", infoRouteHandler)
		http.HandleFunc("/healthz", healthzRouteHandler)
		http.HandleFunc("/readyz", healthzRouteHandler)
		http.HandleFunc("/ca-cert", caCertRouteHandler)

		fmt.Printf("Listening on port 5555\n")
		http.ListenAndServe(":5555", nil)

	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.kcas.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	//rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	rootCmd.Flags().StringVar(&cmName, "configmap-name", "kube-root-ca.crt", "name of the configmap that houses the Kubernetes API Server CA Certificate")
	rootCmd.Flags().StringVar(&cmNamespace, "configmap-namespace", "kube-system", "name of the namespace where the configmap is located")
	rootCmd.Flags().StringVar(&cmKey, "configmap-key", "ca.crt", "name of the namespace where the configmap is located")
	rootCmd.Flags().StringVar(&kubeconfig, "kubeconfig", "", "name of the kubeconfig file to use. Leave blank for default/in-cluster")
	rootCmd.Flags().StringVar(&kubeContext, "context", "", "name of the kubeconfig context to use. Leave blank for default")
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)

		// Search config in home directory with name ".kcas" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigType("yaml")
		viper.SetConfigName(".kcas")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}
}

// caCertRouteHandler handles calls for the "/ca-cert" route
// This route reads the K8s API Server CA Cert from a configMap and prints it out
func caCertRouteHandler(w http.ResponseWriter, req *http.Request) {

	// Print current CA Cert
	cmClient.mutex.Lock()
	body := []byte(fmt.Sprintf("%v", cmClient.caCert))
	cmClient.mutex.Unlock()
	w.WriteHeader(http.StatusOK)
	w.Write(body)

	fmt.Printf("%q\tendpoint called [ Method: %q,\tProtocol: %q, User Agent: %q ]\n", req.RequestURI, req.Method, req.Proto, req.Header.Get("User-Agent"))
}

// infoRouteHandler handles calls for the "/info" route
// This route ouputs info about the environment/K8s CA Cert
func infoRouteHandler(w http.ResponseWriter, req *http.Request) {

	var responseInfo infoResponse

	// Decode Cert string to PEM
	pemCert, _ := pem.Decode([]byte(cmClient.caCert))
	if pemCert == nil {
		fmt.Println(pemCert)
		panic("Unable to decode K8s CA Cert")
	}

	// Parse PEM Cert
	parsedCert, err := x509.ParseCertificate([]byte(pemCert.Bytes))
	if err != nil {
		panic("Unable to parse K8s CA Cert:" + err.Error())
	}

	// Calculate days until CA Cert Expires
	caDays := time.Until(parsedCert.NotAfter).Hours() / 24

	// Set Response Body
	cmClient.mutex.Lock()
	responseInfo.Cluster = os.Getenv(CLUSTER_ENV)
	responseInfo.Pod = os.Getenv(POD_ENV)
	responseInfo.Datetime = time.Now()
	responseInfo.CaDaysToExpire = int(caDays)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(responseInfo)
	cmClient.mutex.Unlock()

	fmt.Printf("%q\tendpoint called [ Method: %q, Protocol: %q, User Agent: %q ]\n", req.RequestURI, req.Method, req.Proto, req.Header.Get("User-Agent"))
}

// healthzRouteHandler/readyzRouteHandler handles calls for the "/healthz" and "/readyz" routes
// This route outputs the current health/ready status of the app
func healthzRouteHandler(w http.ResponseWriter, req *http.Request) {

	// Decode Cert string to PEM
	pemCert, _ := pem.Decode([]byte(cmClient.caCert))
	if pemCert == nil {
		fmt.Println(pemCert)
		panic("Unable to decode K8s CA Cert")
	}

	// Parse PEM Cert
	parsedCert, err := x509.ParseCertificate([]byte(pemCert.Bytes))
	if err != nil {
		panic("Unable to parse K8s CA Cert:" + err.Error())
	}

	// Set cert info for validation
	issuer := parsedCert.Issuer.CommonName
	subject := parsedCert.Subject.CommonName
	response := make(map[string]string)

	// Set route type based on whether it's called as "/readyz" or "/healthz"
	routeType := "healthy"
	if req.RequestURI == "/readyz" {
		routeType = "ready"
	}

	// Validate we're getting a Cert with loose correlation to the K8s API Server
	// TODO: See if maybe there's more we can validate here
	if cmClient.caCert != "" && issuer == "kubernetes" && subject == "kubernetes" {
		response[routeType] = "true"
		w.WriteHeader(http.StatusOK)
	} else {
		response[routeType] = "false"
		w.WriteHeader(http.StatusServiceUnavailable)
	}

	// Set Response Body
	cmClient.mutex.Lock()
	w.Header().Set("Content-Type", "application/json")
	jsonResponse, err := json.Marshal(response)
	if err != nil {
		panic("Unable to marshal response body to JSON" + err.Error())
	}
	w.Write(jsonResponse)
	cmClient.mutex.Unlock()

	fmt.Printf("%q\tendpoint called [ Method: %q, Protocol: %q, User Agent: %q ]\n", req.RequestURI, req.Method, req.Proto, req.Header.Get("User-Agent"))
}

// watchConfigMap to stand up a watcher for the configMap
func watchConfigMap(cmClient *cmConfig) {

	// Set options to filter for a single configMap object
	cmOptions = metav1.SingleObject(metav1.ObjectMeta{Name: cmName, Namespace: cmNamespace})

	// Watch for events on configMap
	for {
		watcher, err := cmClient.k8sInterface.CoreV1().ConfigMaps(cmNamespace).Watch(context.TODO(), cmOptions)
		if err != nil {
			panic("Unable to create watcher")
		}

		// Update CA Cert value
		updateCACert(watcher.ResultChan(), cmClient)
	}
}

// updateCACert updates the CA Cert value upon configMap changes
func updateCACert(eventChannel <-chan watch.Event, cmClient *cmConfig) {
	// React to incoming events on the channel
	for {
		event, open := <-eventChannel

		if open {

			// Parse based on incoming event type
			switch event.Type {

			// Handle Object added
			case watch.Added:

				fallthrough

			// Handle object modified
			case watch.Modified:

				fmt.Printf("Target configmap \"%v/%v\" has been modified\n", cmNamespace, cmName)

				// Update the CA Cert
				cmClient.mutex.Lock()
				if cm, ok := event.Object.(*corev1.ConfigMap); ok {
					fmt.Printf("Object retrieved from watcher is of Kind ConfigMap\n")
					if cmValue, ok := cm.Data[cmKey]; ok {
						fmt.Printf("Object retrieved from watcher has data key %q\n", cmKey)
						cmClient.caCert = cmValue
						fmt.Printf("Updating CA\n")
					} else {
						fmt.Printf("Not updating CA\n")
					}
				} else {
					fmt.Printf("Object retrieved from watcher is not a ConfigMap")
				}
				cmClient.mutex.Unlock()

			// Handle object deleted
			case watch.Deleted:

				fmt.Printf("Target configmap \"%v/%v\" has been deleted\n", cmNamespace, cmName)

				// Fall back to the default value
				cmClient.mutex.Lock()
				cmClient.caCert = defaultCertValue
				fmt.Printf("Setting default value: %v\n", cmClient.caCert)
				cmClient.mutex.Unlock()

			default:
				// Do nothing
			}
		} else {
			// If eventChannel is closed, it means the server has closed the connection
			return
		}
	}
}
