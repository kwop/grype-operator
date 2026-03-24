# grype-operator

Operateur Kubernetes qui scanne automatiquement les images des pods en cours d'execution avec [Grype](https://github.com/anchore/grype) et expose les resultats en CRDs + metriques Prometheus.

Cree en remplacement de `trivy-operator` suite a la supply chain attack TeamPCP (mars 2026).

## Fonctionnement

```
                          Kubernetes Cluster
 ┌──────────────────────────────────────────────────────────────┐
 │                                                              │
 │   ┌─────────┐    watch     ┌──────────────────────────────┐  │
 │   │  Pod A   │◄────────────│                              │  │
 │   │ nginx:1  │             │      grype-operator          │  │
 │   └─────────┘              │                              │  │
 │                            │  1. Watch Pod create/update   │  │
 │   ┌─────────┐    watch     │  2. Extract image + digest    │  │
 │   │  Pod B   │◄────────────│  3. Check cache (skip dups)   │  │
 │   │ redis:7  │             │  4. Create ImageScan CRD      │  │
 │   └─────────┘              │  5. Run grype scan            │  │
 │                            │  6. Update CRD status         │  │
 │   ┌─────────┐    watch     │  7. Export Prometheus metrics  │  │
 │   │  Pod C   │◄────────────│                              │  │
 │   │ myapp:v2 │             └──────────┬───────────────────┘  │
 │   └─────────┘                         │                      │
 │                                       │                      │
 │                              ┌────────▼────────┐             │
 │                              │  ImageScan CRDs  │             │
 │                              │                  │             │
 │                              │ nginx:1          │             │
 │                              │  Critical: 2     │             │
 │                              │  High: 5         │             │
 │                              │                  │             │
 │                              │ redis:7          │             │
 │                              │  Critical: 0     │             │
 │                              │  High: 1         │             │
 │                              └─────────────────┘             │
 │                                                              │
 └──────────────────────────────────────────────────────────────┘
                                 │
                          :8080/metrics
                                 │
                    ┌────────────▼────────────┐
                    │      Prometheus          │
                    │                          │
                    │ grype_operator_vulns     │
                    │ grype_operator_scans     │
                    │ grype_operator_duration  │
                    └────────────┬────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │       Grafana            │
                    │                          │
                    │ Dashboard JSON inclus    │
                    │ grafana/dashboard.json   │
                    └─────────────────────────┘
```

### Cycle de scan detaille

```
 Pod cree/modifie
        │
        ▼
 ┌──────────────┐     oui     ┌─────────┐
 │  Namespace    │────────────►│  SKIP   │
 │  exclu ?      │             └─────────┘
 └──────┬───────┘
        │ non
        ▼
 ┌──────────────┐     oui     ┌─────────┐
 │  Image        │────────────►│  SKIP   │
 │  exclue ?     │             └─────────┘
 └──────┬───────┘
        │ non
        ▼
 ┌──────────────┐     oui     ┌─────────┐
 │  Digest dans  │────────────►│  SKIP   │
 │  le cache ?   │             └─────────┘
 └──────┬───────┘
        │ non
        ▼
 ┌──────────────┐
 │  Creer CRD   │
 │  ImageScan    │
 │  (Pending)    │
 └──────┬───────┘
        │
        ▼
 ┌──────────────┐
 │  grype scan   │
 │  (subprocess) │
 └──────┬───────┘
        │
        ▼
 ┌──────────────┐
 │  Mettre a     │
 │  jour CRD     │
 │  (Completed)  │
 │  + metrics    │
 │  + cache      │
 └──────────────┘
```

## Prerequis

- Go 1.22+
- Docker
- kubectl
- Acces a un cluster Kubernetes 1.29+

## Installation

### Via Helm (recommande)

Le chart Helm se trouve dans le repo [infra-paramedic](https://github.com/kwop/infra-paramedic) :

```sh
helm install grype-operator helm-paramedic/grype-operator/ \
  -f helm-paramedic/grype-operator/values.yaml \
  -f helm-paramedic/grype-operator/values-gcp.yaml \
  -n grype-operator --create-namespace
```

### Via Kustomize

```sh
# Installer les CRDs
make install

# Deployer l'operateur
make deploy IMG=kwop/grype-operator:v0.1.0
```

### Via Docker Hub

L'image est disponible sur Docker Hub :

```sh
docker pull kwop/grype-operator:latest
```

## Configuration

| Parametre | Defaut | Description |
|-----------|--------|-------------|
| `--exclude-namespaces` | `kube-system` | Namespaces a ignorer (glob, comma-separated) |
| `--exclude-images` | _(vide)_ | Images a ignorer (glob, comma-separated) |
| `--scan-timeout` | `5m` | Timeout par scan Grype |
| `--cache-ttl` | `24h` | Duree de cache par digest |
| `--scan-concurrency` | `3` | Scans simultanees max |
| `--min-severity` | `medium` | Severite minimale dans les resultats |
| `--db-update-interval` | `12h` | Intervalle de mise a jour de la DB Grype |
| `--leader-elect` | `false` | Active le leader election (multi-replica) |

## CRD ImageScan

L'operateur cree un `ImageScan` par image unique detectee dans le cluster :

```yaml
apiVersion: security.paramedic.tech/v1alpha1
kind: ImageScan
metadata:
  name: scan-nginx-1-25-3-abcdef123456
  namespace: production
spec:
  image: nginx:1.25.3
  digest: sha256:abcdef123456...
  sourceNamespace: production
  sourcePod: web-frontend-abc123
status:
  phase: Completed
  lastScanTime: "2026-03-24T20:00:00Z"
  summary:
    critical: 2
    high: 5
    medium: 12
    low: 3
    unknown: 0
  vulnerabilities:
    - id: CVE-2024-12345
      severity: Critical
      package: openssl
      version: 3.0.1
      fixedIn: 3.0.15
```

Consulter les scans :

```sh
# Tous les scans
kubectl get imagescans -A

# Scans avec details (printer columns)
kubectl get imagescans -A -o wide

# Detail d'un scan
kubectl describe imagescan scan-nginx-1-25-3-abcdef123456 -n production
```

## Metriques Prometheus

| Metrique | Type | Labels | Description |
|----------|------|--------|-------------|
| `grype_operator_vulnerabilities_total` | Gauge | image, namespace, severity | Nombre de vulns par image/namespace/severite |
| `grype_operator_scan_duration_seconds` | Histogram | image | Duree des scans |
| `grype_operator_scans_total` | Counter | status | Nombre total de scans (completed/failed) |
| `grype_operator_images_scanned` | Gauge | - | Nombre d'images uniques suivies |
| `grype_operator_cache_size` | Gauge | - | Taille du cache |
| `grype_operator_db_last_update_timestamp` | Gauge | - | Timestamp derniere MAJ DB Grype |

Un dashboard Grafana est inclus dans `grafana/dashboard.json`.

## Developpement

```sh
# Lancer les tests
make test

# Lancer les tests avec race detector
go test -race ./internal/cache/ ./internal/scanner/

# Lancer le linter
make lint

# Generer les CRDs apres modification des types
make manifests

# Generer le deepcopy apres modification des types
make generate

# Build local
make build
```

## Architecture

```
grype-operator/
├── api/v1alpha1/           # CRD ImageScan types
├── cmd/                    # Point d'entree, flags, setup manager
├── internal/
│   ├── controller/
│   │   ├── pod_controller.go       # Watch pods → cree ImageScan
│   │   └── imagescan_controller.go # Scan Grype → met a jour status
│   ├── scanner/            # Interface Grype (subprocess)
│   ├── cache/              # Cache in-memory par digest
│   └── metrics/            # Metriques Prometheus
├── config/                 # Kustomize (CRDs, RBAC, manager)
├── grafana/                # Dashboard Grafana JSON
└── Dockerfile              # Multi-stage : Go + binaire Grype
```

## Licence

Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
