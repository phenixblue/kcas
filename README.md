# kcas

Application to discover and serve the Kubernetes API CA Cert

Useful for scenarios where you want to make the CA Cert discoverable outside of a cluster

## Usage

```
A utility to discover and serve the Kubernetes API Server CA Certificate to a target cluster

Usage:
  kcas [flags]

Flags:
      --config string                config file (default is $HOME/.kcas.yaml)
      --configmap-key string         name of the namespace where the configmap is located (default "ca.crt")
      --configmap-name string        name of the configmap that houses the Kubernetes API Server CA Certificate (default "kube-root-ca.crt")
      --configmap-namespace string   name of the namespace where the configmap is located (default "kube-system")
      --context string               name of the kubeconfig context to use. Leave blank for default
  -h, --help                         help for kcas
      --kubeconfig string            name of the kubeconfig file to use. Leave blank for default/in-cluster
```
