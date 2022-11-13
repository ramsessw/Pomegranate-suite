import json
import collections
import xml.etree.ElementTree as ET
import json

Number_of_Practises = 18

# Policy Ref: https://github.com/tenable/terrascan/tree/master/docs/policies
policy_match_terrascan = {3: 'AC_DOCKER',
                          11: 'AC_AWS',
                          13: 'AC_K8S',
                          18: 'AC_K8S_0002'
                          }
# Policy Ref: https://www.cisecurity.org/benchmark/docker
policy_match_dockerbench = {2: ['3'],
                            3: ['1', '2', '4', '5', '6', '7'],
                            }
# Policy Ref: https://www.cisecurity.org/benchmark/kubernetes
policy_match_kubebench = {4: '1.2',
                          5: '5.1',
                          6: '5.1',
                          7: '5.2',
                          8: '2.',
                          10: '5.4',
                          13: 'All',
                          14: '4.2'
                          }
# Policy Ref: https://aquasecurity.github.io/kube-hunter/kbindex.html
policy_match_kubehunter = {2: ['KHV044'],
                           4: ['KHV006'],
                           5: ['KHV005', 'KHV050'],
                           6: ['KHV007'],
                           8: ['KHV031', 'KHV032', 'KHV033', 'KHV034'],
                           9: ['KHV002'],
                           11: ['KHV052'],
                           12: ['KHV002'],
                           13: ['All'],
                           14: ['KHV046'],
                           15: ['KHV005', 'KHV006', 'KHV007', 'KHV023'],
                           }
# https://www.zaproxy.org/docs/alerts/
policy_match_zap = {16: 'All',
                    18: '40036',
                    }
policy_match_nmap_port = 17
policy_match_nmap_ssl = 18
# Policy Ref: https://avd.aquasec.com/
policy_match_trivy = [1, 2, 3]
intential_open_ports = ['8080']


class Results:
    def __init__(self):
        self.final_results = collections.defaultdict(dict)
        self.docs = collections.defaultdict(set)
        for i in range(1, Number_of_Practises+1):
            self.final_results[i]['status'] = False

    def set_weakness(self, id, doc):
        self.final_results[id]['status'] = True
        self.docs[doc].add(id)

    def get_results(self):
        for i in self.final_results:
            print(self.final_results[i]['status'])

    def get_result(self, id):
        return self.final_results[id]['status']

    def get_docs(self):
        return self.docs


def matchingKeys(dictionary, id):
    return [key for key, val in dictionary.items() if any(id in s for s in val)]


def parse_terrascan(res):
    with open('./reports/terrascan-report.json') as f:
        report = json.load(f)

    for v in report['results']['violations']:
        for key, value in policy_match_terrascan.items():
            if value in v['rule_id']:
                res.set_weakness(key, f.name)

    f.close()


def parse_dockerbenchsec(res):
    with open('./reports/docker-bench-report.json') as f:
        report = json.load(f)

    for v in report['tests'][0]['results']:
        if v['result'] == 'WARN':
            for i in matchingKeys(policy_match_dockerbench, report['tests'][0]['id']):
                res.set_weakness(i, f.name)

    f.close()


def parse_kubebench(res):

    def set(id):
        for key, value in policy_match_kubebench.items():
            if id.startswith(value):
                res.set_weakness(key, f.name)
                return
        res.set_weakness(14, f.name)

    with open('./reports/kube_bench_report') as f:
        for line in f:
            if line[0] == '[':
                split = line.split(' ')
                id = split[1]
                status = split[0][1:5]
                if status == 'FAIL' or status == 'WARN':
                    set(id)

    f.close()


def parse_kubehunter(res):
    with open('./reports/kube_hunter_report') as f:
        for line in f:
            if 'KHV' in line:
                id = line[2:8]
                for i in matchingKeys(policy_match_kubehunter, id):
                    res.set_weakness(i, f.name)

    f.close()


def parse_nmap_port(res):
    file_name = 'nmap-port-report.xml'
    tree = ET.parse('./reports/' + file_name)
    root = tree.getroot()
    for x in root.iter('port'):
        if not x.attrib['portid'] in intential_open_ports:
            res.set_weakness(
                policy_match_nmap_port, file_name)


def parse_nmap_ssl(res):
    file_name = 'nmap-ssl-report.xml'
    tree = ET.parse('./reports/' + file_name)
    root = tree.getroot()
    for x in root.iter('service'):
        if x.attrib['name'] == 'http':
            res.set_weakness(
                policy_match_nmap_ssl, file_name)


def parse_trivy(res):
    with open('./reports/trivy-results.json', encoding="utf8") as f:
        report = json.load(f)

    if report['Vulnerabilities'][0]['Results']:
        res.set_weakness(policy_match_trivy[0], f.name)

    for i in report['Misconfigurations']:
        try:
            for j in i['Results']:
                if j['Type'] == 'kubernetes':
                    if j['MisconfSummary']['Failures'] > 0:
                        res.set_weakness(policy_match_trivy[1], f.name)
        except KeyError:
            pass

    for i in report['Vulnerabilities']:
        try:
            for j in i['Results']:
                if j['Target'] == 'Dockerfile':
                    if j['MisconfSummary']['Failures'] > 0:
                        res.set_weakness(policy_match_trivy[2], f.name)
        except KeyError:
            pass

    f.close()


def parse_zap(res):
    with open('./reports/zap-report.json') as f:
        report = json.load(f)

    for v in report['site'][0]['alerts']:
        for key, value in policy_match_zap.items():
            if value == v['pluginid'] or value == 'All':
                res.set_weakness(key, f.name)

    f.close()


def create_result_file(res):
    with open(f"./summary.md", "w") as f:
        with open('./template_table') as t:
            id = 1
            docs = {}
            for num, line in enumerate(t, 1):
                if num <= 2 or id > Number_of_Practises:
                    f.write(line)
                    continue

                status = '&#10004;'

                if res.get_result(id):
                    status = '&#10005;'

                f.write(
                    f"{line[:-1]}{status}|\n")
                id += 1

        for key, value in res.get_docs().items():
            f.write(
                f"|{key}|S{value}|\n")


def main():
    res = Results()
    parse_terrascan(res)
    parse_kubebench(res)
    parse_kubehunter(res)
    parse_nmap_port(res)
    parse_nmap_ssl(res)
    parse_trivy(res)
    parse_dockerbenchsec(res)
    parse_zap(res)
    # res.get_results()
    create_result_file(res)


if __name__ == "__main__":
    main()

