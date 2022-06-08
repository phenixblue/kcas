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

## Use Cases

### Serve K8s API CA Cert

Sometimes you may have a need to expose the K8s API Server CA Cert external to a given cluster.

#### Standard Install

```shell
$ make install
```

This will create the `kcas-system` namespace and deploy all other resources there

This configuration will look for the `kube-root-ca.crt` configmap in the `kcas-system` namespace and serve that contents on `/ca-cert`

#### Standalone Install

```shell
$ make install-standalone namespace=target-namespace
```

This will deploy all resources except for the namespace and cluster scoped RBAC resources into the namespace specified.

This configuration will look for the `kube-root-ca.crt` configmap in the target namespace and serve that contents on `/ca-cert`

### Serve data from an arbitrary configMap

You want to serve some data from a configmap other than the k8s API Server CA Cert. To do this, you need to change the arguments in the deployment similar to this:

```yaml
args:
  - "--configmap-namespace=target-namespace"
  - "--configmap-name=my-cool-configmap"
  - "--configmap-name=my-config.yaml"
  - "--disable-tls-processing"
```

The specific arguments and values will differ based on use case and environment, so these serve only as one possible example.
