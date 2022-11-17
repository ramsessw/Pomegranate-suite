import json
import collections
import xml.etree.ElementTree as ET
import json
from collections import OrderedDict

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
                           # 9: ['KHV002'],
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


class Output:
    def __init__(self, title, desc, severity, source):
        self.title = title
        self.desc = desc
        self.severity = severity
        self.source = source


class Results:
    def __init__(self):
        self.final_results = collections.defaultdict(dict)
        self.out = OrderedDict()
        for i in range(1, Number_of_Practises+1):
            self.final_results[i]['status'] = False
            self.out[i] = []

    def set_weakness(self, id, out):
        self.final_results[id]['status'] = True
        self.out[id].append(out)

    def get_results(self):
        for i in self.final_results:
            print(self.final_results[i]['status'])

    def get_result(self, id):
        return self.final_results[id]['status']

    def writeOutput(self):
        for i in range(1, Number_of_Practises+1):
            if self.out[i]:
                j = json.dumps(self.out[i], default=lambda o: o.__dict__,
                               sort_keys=True,  indent=4)
                with open('./output/S' + str(i) + '.json', 'w') as f:
                    f.write(j)
                f.close()


def matchingKeys(dictionary, id):
    return [key for key, val in dictionary.items() if any(id in s for s in val)]


def parse_terrascan(res):
    with open('./reports/terrascan-report.json') as f:
        report = json.load(f)

    for v in report['results']['violations']:
        for key, value in policy_match_terrascan.items():
            if value in v['rule_id']:
                o = Output(
                    v['rule_name'], v['description'], v['severity'], f.name)
                res.set_weakness(key, o)

    f.close()


def parse_dockerbenchsec(res):
    with open('./reports/docker-bench-report.json') as f:
        report = json.load(f)

    for v in report['tests'][0]['results']:
        if v['result'] == 'WARN':
            for i in matchingKeys(policy_match_dockerbench, report['tests'][0]['id']):
                o = Output(
                    report['tests'][0]['desc'], v['desc'], v['result'], f.name)
                res.set_weakness(i, o)

    f.close()


def parse_kubebench(res):

    def set(id, o):
        for key, value in policy_match_kubebench.items():
            if id.startswith(value):
                res.set_weakness(key, o)
                return
        res.set_weakness(14, o)

    with open('./reports/kube_bench_report') as f:
        for line in f:
            if line[0] == '[':
                split = line.split(' ')
                id = split[1]
                status = split[0][1:5]
                if status == 'FAIL':
                    o = Output(
                        line[7:], line[7:], 'MEDIUM', f.name)
                    set(id, o)

    f.close()


def parse_kubehunter(res):
    with open('./reports/kube_hunter_report') as f:
        id, desc, title = '', '', ''
        for line in f:
            if line[0] == '+':
                if id != '':
                    desc = " ".join(desc.split())
                    title = " ".join(title.split())
                    for i in matchingKeys(policy_match_kubehunter, id):
                        o = Output(
                            title, desc, 'MEDIUM', f.name)
                        res.set_weakness(i, o)
                    id, desc, title = '', '', ''
            elif 'KHV' in line:
                id = line[2:8]
                desc, title = '', ''

            if len(line) >= 125:
                desc += line[80:101]
                title += line[57:78]
    f.close()


def parse_nmap_port(res):
    file_name = 'nmap-port-report.xml'
    tree = ET.parse('./reports/' + file_name)
    root = tree.getroot()
    for x in root.iter('port'):
        if not x.attrib['portid'] in intential_open_ports:
            o = Output(
                'Open ports', 'Disable port if it is not intentionally used:' + x.attrib['portid'], 'HIGH', file_name)
            res.set_weakness(
                policy_match_nmap_port, o)


def parse_nmap_ssl(res):
    file_name = 'nmap-ssl-report.xml'
    tree = ET.parse('./reports/' + file_name)
    root = tree.getroot()
    for x in root.iter('service'):
        if x.attrib['name'] == 'http':
            o = Output(
                'Non-Secured Service-to-Service Communications', 'Use secure SSL/TLS Algorithms for ' + x.attrib['product'], 'HIGH', file_name)
            res.set_weakness(
                policy_match_nmap_ssl, o)


def parse_trivy(res):
    with open('./reports/trivy-results.json', encoding="utf8") as f:
        report = json.load(f)

    try:
        for j in report['Vulnerabilities'][0]['Results']:
            for k in j['Vulnerabilities']:
                o = Output(
                    k['VulnerabilityID'], k['Description'], k['Severity'], f.name)
                res.set_weakness(policy_match_trivy[0], o)
    except KeyError:
        pass

    for i in report['Misconfigurations']:
        try:
            for j in i['Results']:
                if j['Type'] == 'kubernetes':
                    for k in j['Misconfigurations']:
                        o = Output(
                            k['Title'], k['Description'], k['Severity'], f.name)
                        res.set_weakness(policy_match_trivy[1], o)
        except KeyError:
            pass

    for i in report['Vulnerabilities']:
        try:
            for j in i['Results']:
                if j['Target'] == 'Dockerfile':
                    for k in j['Misconfigurations']:
                        o = Output(
                            k['Title'], k['Description'], k['Severity'], f.name)
                        res.set_weakness(policy_match_trivy[2], o)
        except KeyError:
            pass

    f.close()


def parse_zap(res):
    with open('./reports/zap-report.json') as f:
        report = json.load(f)

    for v in report['site'][0]['alerts']:
        for key, value in policy_match_zap.items():
            if value == v['pluginid'] or value == 'All':
                o = Output(
                    v['name'], v['desc'], v['riskdesc'], f.name)
                res.set_weakness(key, o)

    f.close()


def create_result_file(res):
    with open(f"./summary.md", "w") as f:
        with open('./template_table') as t:
            id = 1
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
    res.writeOutput()
    create_result_file(res)


if __name__ == "__main__":
    main()
