| Category   | Security Defect                                      | Security Practice                                                        | Id | Status |
|------------|------------------------------------------------------|--------------------------------------------------------------------------|--------|--------|
| Container  | Vulnerable container images                          | Prevent containers from loading vulnerable kernel modules                | S1     |&#10005;|
|            | Unnecessary Privileges                               | Follow The Least Privilege Principle                                     | S2     |&#10005;|
|            | Faulty container configuration                       | Audit and harden container configuration files                           | S3     |&#10005;|
| Kubernetes | Unauthorized access through Kubernetes cluster       | Use Transport Layer Security (TLS) for all API traffic                   | S4     |&#10005;|
|            |                                                      | Use Service Accounts                                                     | S5     |&#10005;|
|            |                                                      | Use Role Base Access Control (RBAC)                                      | S6     |&#10004;|
|            | Unlimited resource usage and capabilities on cluster | Restrict resource usage, user capabilities and network access on cluster | S7     |&#10005;|
|            | Explosure of cluster components                      | Restrict access to etcd                                                  | S8     |&#10004;|
|            |                                                      | Restrict access to alpha or beta features                                | S9     |&#10005;|
|            |                                                      | Use and encrypt Kubernetes Secrets                                       | S10    |&#10005;|
|            |                                                      | Use network policies to restrict pod access on cloud                     | S11    |&#10004;|
|            |                                                      | Use latest version and check vulnerability updates continuously          | S12    |&#10005;|
|            | Kubernetes misconfiguration                          | Audit and harden Kubernetes configuration files                          | S13    |&#10005;|
|            | Unauthenticated access to Kubelet                    | Enable Kubelet authentication and authorization                          | S14    |&#10005;|
| Network    | Exposing service to external consumers without protection | Use API Gateway to expose services and Oauth 2.0 for API security   | S15    |&#10005;|
|            |                                                           | Prevent vulnerabilities in URL endpoints                            | S16    |&#10005;|
|            |                                                           | Disable exposing unnecessary open-ports externally                  | S17    |&#10005;|
|            | Non-Secured Service-to-Service Communications             | Use Mutual TLS and/or JSON Web Token (JWT)                          | S18    |&#10005;|


Please check following reports to apply security practises:  

| Report       | Id                |
|--------------|-------------------|

|./reports/terrascan-report.json|S{3, 13}|
|./reports/kube_bench_report|S{4, 5, 7, 10, 14}|
|./reports/kube_hunter_report|S{9, 12, 5, 15}|
|nmap-port-report.xml|S{17}|
|nmap-ssl-report.xml|S{18}|
|./reports/trivy-results.json|S{1, 2, 3}|
|./reports/docker-bench-report.json|S{3}|
|./reports/zap-report.json|S{16}|
