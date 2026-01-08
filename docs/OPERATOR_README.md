

## Add the Helm repo

```sh
helm repo add arxignis https://helm.gen0sec.com
helm repo update
helm search repo arxignis
# gen0sec/synapse
# gen0sec/synapse-stack
```

## Install

```sh
# set your API key
export ARX_KEY="REPLACE_ME"

# pick a chart version (see `helm search repo arxignis` for latest)
export MOAT_STACK_VER="0.1.2"

helm upgrade --install synapse-stack gen0sec/synapse-stack \
  --version "$MOAT_STACK_VER" \
  -n synapse --create-namespace \
  --set global.namespaces.synapse="synapse" \
  --set global.namespaces.operator="synapse-system" \
  --set synapse.image.repository="ghcr.io/gen0sec/synapse" \
  --set synapse.image.tag="latest" \
  --set synapse.synapse.server.upstream="http://example.com" \
  --set synapse.synapse.network.disableXdp=true \
  --set synapse.synapse.arxignis.apiKey="$ARX_KEY" \
  --set synapse.synapse.contentScanning.scanExpression='http.request.method eq "POST" or http.request.method eq "PUT"' \
  --set operator.enabled=true \
  --set operator.createNamespace=true \
  --set operator.image.repository="ghcr.io/gen0sec/synapse-operator" \
  --set operator.image.tag="latest"
```

Wait for rollouts:

```sh
kubectl -n synapse rollout status deploy/synapse-stack
kubectl -n synapse-system rollout status deploy/synapse-operator
```

## Configure via `values.yaml`

```yaml
global:
  namespaces:
    synapse: synapse
    operator: synapse-system

synapse:
  replicaCount: 1
  image:
    repository: ghcr.io/gen0sec/synapse
    tag: latest
    pullPolicy: IfNotPresent

  synapse:
    server:
      # Where Synapse proxies to by default (change to your origin)
      upstream: "http://example.com"
    network:
      # Disable XDP for environments without eBPF/XDP
      disableXdp: true
    arxignis:
      # Prefer to set via --set or Secrets in production
      apiKey: "REPLACE_ME"
    contentScanning:
      # Only scan bodies on POST/PUT in this example
      scanExpression: 'http.request.method eq "POST" or http.request.method eq "PUT"'

operator:
  enabled: true
  createNamespace: true
  image:
    repository: ghcr.io/gen0sec/synapse-operator
    tag: latest
    pullPolicy: IfNotPresent
  replicaCount: 1
  leaderElect: true
  serviceAccount:
    create: true
    name: ""
  rbac:
    create: true
  resources:
    requests:
      cpu: 5m
      memory: 32Mi
    limits:
      cpu: 200m
      memory: 128Mi
```

Install with:

```sh
helm upgrade --install synapse-stack gen0sec/synapse-stack \
  --version "$MOAT_STACK_VER" \
  -n synapse --create-namespace \
  -f values.yaml
```
