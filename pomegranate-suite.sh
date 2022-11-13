#!/bin/bash

# Run docker-bench-security scanner
echo “Running docker-bench-security.”
cd $WRKDIR/tools/docker-bench-security
sudo sh docker-bench-security.sh -p -l docker-bench-report
mv docker-bench-report.json $WRKDIR/reports/
cd $WRKDIR

# Run trivy scanner
echo “Running trivy.”
trivy k8s --format json -o $WRKDIR/reports/trivy-results.json cluster --timeout 1h

# Run kube-hunter scanner
kubectl apply -f $WRKDIR/tools/kube-hunter-job.yaml
echo “Waiting for kube-hunter pod ready.”
kubectl wait --for=condition=ready pod -l app=kube-hunter --timeout=2m
echo “Waiting for kube-hunter job completed.”
kubectl wait --for=condition=complete job/kube-hunter --timeout=10m
POD=$(kubectl get pod -l app=kube-hunter -o jsonpath="{.items[0].metadata.name}")
kubectl logs $POD > $WRKDIR/reports/kube_hunter_report
kubectl delete -f $WRKDIR/tools/kube-hunter-job.yaml

# Run kube-bench scanner
kubectl apply -f $WRKDIR/tools/kube-bench-job.yaml
echo “Waiting for kube-bench pod ready.”
kubectl wait --for=condition=ready pod -l app=kube-bench --timeout=2m
echo “Waiting for kube-bench job completed.”
kubectl wait --for=condition=complete job/kube-bench --timeout=10m
POD=$(kubectl get pod -l app=kube-bench -o jsonpath="{.items[0].metadata.name}")
kubectl logs $POD > $WRKDIR/reports/kube_bench_report
kubectl delete -f $WRKDIR/tools/kube-bench-job.yaml

# Run OWASP ZAP scanner
echo “Running OWASP ZAP.”
docker run -v $(pwd):/zap/wrk/:rw -t owasp/zap2docker-stable zap-baseline.py -t http://$(ip -f inet -o addr show docker0 | awk '{print $4}' | cut -d '/' -f 1):3000 -J zap-report
mv zap-report* $WRKDIR/reports/

# Run NMAP scanner
echo “Running NMAP.”
PODIPs=$(kubectl get pods -o=jsonpath="{range .items[*]}{.status.podIP}{' '}{end}")
nmap -sV -p 1-65535 $PODIPs -oX $WRKDIR/reports/nmap-port-report.xml
nmap -sV --script ssl* $PODIPs -oX $WRKDIR/reports/nmap-ssl-report.xml

# Run Terrascan
echo “Running Terrascan.”
cd $WRKDIR/apps/redis-operator
terrascan scan -o json > $WRKDIR/reports/terrascan-report.json
cd $WRKDIR

echo “Automated scan completed.”

echo “Started parsing reports.”
python3 parser.py
echo “Summary for results is created: summary.md”
