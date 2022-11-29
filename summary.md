| Category   | Security Defect                                      | Security Practice                                                        | Id | Status |
|------------|------------------------------------------------------|--------------------------------------------------------------------------|--------|--------|
| Container  | Vulnerable container images                          | Prevent containers from loading vulnerable software libraries            | S1     |&#10004;|
|            | Unnecessary Privileges                               | Use authentication and follow The Least Privilege Principle              | S2     |&#10005;|
|            | Faulty container configuration                       | Audit and harden container configuration files                           | S3     |&#10005;|
| Kubernetes | Malicious  access through Kubernetes cluster         | Use Transport Layer Security (TLS) for all API traffic                   | S4     |&#10005;|
|            |                                                      | Use Service Accounts  API Authentication                                 | S5     |&#10005;|
|            |                                                      | Use Role Base Access Control (RBAC) for API Authorization                 | S6     |&#10004;|
|            | Unlimited resource usage and capabilities on cluster | Restrict resource usage, user capabilities and network access on cluster | S7     |&#10004;|
|            | Explosure of cluster components                      | Restrict access to etcd                                                  | S8     |&#10004;|
|            |                                                      | Restrict access to alpha or beta features                                | S9     |&#10004;|
|            |                                                      | Use and encrypt Kubernetes Secrets                                       | S10    |&#10004;|
|            |                                                      | Use network policies to restrict pod access on cloud                     | S11    |&#10004;|
|            |                                                      | Use latest version and check vulnerability updates continuously          | S12    |&#10005;|
|            | Kubernetes misconfiguration                          | Audit and harden Kubernetes configuration files                          | S13    |&#10005;|
|            | Unauthenticated access to Kubelet                    | Enable Kubelet authentication and authorization                          | S14    |&#10005;|
| Network    | Exposing service to external consumers without protection | Use API Gateway to expose services and Oauth 2.0 for API security   | S15    |&#10005;|
|            |                                                           | Prevent vulnerabilities in URL endpoints                            | S16    |&#10005;|
|            |                                                           | Disable exposing unnecessary open-ports externally                  | S17    |&#10005;|
|            | Non-Secured Service-to-Service Communications             | Use Mutual TLS and/or JSON Web Token (JWT)                          | S18    |&#10005;|

