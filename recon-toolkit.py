import argparse
import subprocess
from datetime import datetime
from threading import Thread
import re
import json
import requests
from bs4 import BeautifulSoup
import censys.ipv4
from netaddr import *
import os
import dns.resolver

def show_time(text_for_print):
	if args.debug:
		print(text_for_print, datetime.now())
		#print(text_for_print)

def search_subdomains_with_amass(root_domain):
	show_time("amass started")
	args_fc = ("/root/amass_3.0.18_linux_amd64/amass", "enum", "--passive", "-d", root_domain)
	execute_subdomain_searching_subprocess(args_fc)
	show_time("amass finished")

def search_subdomains_with_subfinder(root_domain):
	show_time("subfinder started")
	args_fc = ("/root/work/bin/subfinder", "-d", root_domain, "-silent")
	execute_subdomain_searching_subprocess(args_fc)
	show_time("subfinder finished")

def execute_subdomain_searching_subprocess(arguments_for_command):
	popen = subprocess.Popen(arguments_for_command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
	for line in  popen.stdout:
		ln = line.decode().strip().lower().lstrip('.')
		if (ln != ''):
			new_domain_found = {"domain" : ln}
			if new_domain_found not in subdoamins_found:
				subdoamins_found.append(new_domain_found)

def resolve_subdomains_from_scraping():
	print(len(subdoamins_found), " domains found from scraping")
	args_fc = ("/root/massdns/bin/massdns", "-r", "/root/massdns/lists/reliable_resolvers.txt", "-t", "A", "-o", "S", "--verify-ip", "--quiet")
	list_of_subdomains_to_test = []
	for target in subdoamins_found:
		list_of_subdomains_to_test.append(target["domain"])
	show_time("resolving scraped names started")
	_, resolved_names = execute_massdns(list_of_subdomains_to_test)
	show_time("scraped names resolving finished")
	print(resolved_names, " domain names resolved from scraping")

def brute_subdomains_with_massdns(root_domain):
	show_time("generating list for bruting")
	list_of_subdomains_to_test = []
	#for lines in open("/root/amass_3.0.18_linux_amd64/wordlists/subdomains-top1mil-5000.txt"):
	for lines in open("/root/all.txt"):
		if lines.strip() != "":
			list_of_subdomains_to_test.append(lines.strip() + "." + root_domain)
	domains_count = len(list_of_subdomains_to_test)
	generated = "list for bruting generated: " + str(domains_count) + " to test"
	show_time(generated)
	show_time("brute-forcing subdomains started")
	unique_names, resolved_names = execute_massdns(list_of_subdomains_to_test)
	show_time("brute-forcing subdomains finished")
	print(resolved_names, "domain names found from brute-forcing")
	print(unique_names, " unique domain names found from brute-forcing")

def execute_massdns(domains_to_test):
	args_fc = ("/root/massdns/bin/massdns", "-r", "/root/massdns/lists/reliable_resolvers.txt", "-t", "A", "-o", "S", "--verify-ip", "--quiet")
	subdomains_to_test = '\n'.join(domains_to_test)
	popen = subprocess.Popen(args_fc, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
	stdout, _ = popen.communicate(input=subdomains_to_test.encode())
	str_output = stdout.decode()
	unique_names = 0
	names_resolved = 0
	for line in str_output.splitlines():
		if line != None:
			ln = line.strip()
			if ln != '':
				names_resolved = names_resolved + 1
				new_entry = ln.split()
				new_entry[0] = re.sub('\.$', '', new_entry[0])
				domain = next((target for target in subdoamins_found if target["domain"] == new_entry[0]), False)
				if domain:
					if new_entry[1] == 'A':
						if 'ip' in domain:
							names_resolved = names_resolved - 1
							if new_entry[2] not in domain['ip']:
								domain['ip'].append(new_entry[2])
						else:
							domain['ip'] = []
							domain['ip'].append(new_entry[2])
					elif new_entry[1] == 'CNAME':
						domain['cname'] = new_entry[2]
				else:
					unique_names = unique_names + 1
					if new_entry[1] == 'A':
						subdoamins_found.append({"domain" : new_entry[0], "ip": [new_entry[2]]})
					elif new_entry[1] == 'CNAME':
						subdoamins_found.append({"domain" : new_entry[0], "cname": new_entry[2]})						
	return unique_names, names_resolved

def search_asns(company_name):
	show_time("getting ASNs list")
	cidr_report_page = requests.get('http://www.cidr-report.org/as2.0/autnums.html')
	show_time("ASNs list loaded, starting parsing")
	cidr_report_page_parsed = BeautifulSoup(cidr_report_page.text, 'html.parser')
	asns = cidr_report_page_parsed.pre.contents
	asns.pop(0)
	asns_to_choose = {}
	for company in company_name:
		for as_num,comp in zip(asns[0::2], asns[1::2]):
			if re.search(company, comp, re.IGNORECASE):
				as_number = as_num.string.strip()
				comp_desc = comp.string.strip()
				asn_to_cidr_page = requests.get('http://www.cidr-report.org/cgi-bin/as-report?as=' + as_number + '&view=2.0')
				asn_to_cidr_page_parsed = BeautifulSoup(asn_to_cidr_page.text, 'html.parser')
				if len(asn_to_cidr_page_parsed.find_all('h3', string="NOT Announced")) == 0:
					cidrs = asn_to_cidr_page_parsed.find_all('pre')[2].find_all('a')
					if len(cidrs) != 0:
						cidrs.pop(0)
						correct_cidrs = []
						for cidr in cidrs:
							correct_cidrs.append(cidr.contents[0].string)
						dict_ind_num = len(asns_to_choose)
						print(dict_ind_num, as_number, comp_desc, ', '.join(correct_cidrs))
						asns_to_choose[dict_ind_num] = correct_cidrs
	user_choices_of_correct_asns = [int(x) for x in input('Choose what ASNs will be used in futher recon activities: ').split() if x.isdigit()]
	for choice in user_choices_of_correct_asns:
		if choice in asns_to_choose:
			for asn in asns_to_choose[choice]:
				if asn not in asns_in_scope:
					asns_in_scope.append(asn)
	show_time("searching ASNs finished")

def search_through_censys_for_new_hosts(root_domain):
	show_time("starting censys analysis")
	addressess = {}
	with open('/root/.config/subfinder/config.json') as json_file:
		api_keys = json.load(json_file)
		censys_conn = censys.ipv4.CensysIPv4(api_id=api_keys["censysUsername"], api_secret=api_keys["censysSecret"])
		domain_to_search = re.sub('\.', '\\.', root_domain)
		for censys_search_result in censys_conn.search("443.https.tls.certificate.parsed.extensions.subject_alt_name.dns_names: /.*\." + domain_to_search + "/", ['ip']):
			addressess[censys_search_result['ip']] = None
	show_time("censys analysis finished")
	return addressess

def scan_ports_of_target_hosts():
	targets = list(ip_addresses.keys())
	fifofile = '/tmp/masscan_output'
	args_fc = ["/usr/bin/masscan", "-oJ", fifofile, "-p80,443", "--rate", "17000"]
	args_fc.extend(targets)
	masscan_output_parsed = []
	popen = subprocess.run(args_fc)
	for masscan_line in open(fifofile, 'r'):
		if not re.search("finished", masscan_line, re.IGNORECASE):
			line_to_add = masscan_line.strip().rstrip(',')
			masscan_output_parsed.append(json.loads(line_to_add))
	for result in masscan_output_parsed:
		if 'ports' not in ip_addresses[result['ip']]:
			ip_addresses[result['ip']]['ports'] = []
			ip_addresses[result['ip']]['ports'].append(result['ports'][0]['port'])
		else:
			ip_addresses[result['ip']]['ports'].append(result['ports'][0]['port'])

def resolve_cnames():
	for domain in subdoamins_found:
		if 'cname' in domain:
			try:
				answer = dns.resolver.query(domain['cname'], 'A')
				for answ in answer:
					if 'ip' in domain:
						domain['ip'].append(answ.to_text())
					else:
						domain['ip'] = []
						domain['ip'].append(answ.to_text())
			except Exception:
				pass

time_started = datetime.now()
parser = argparse.ArgumentParser()
parser.add_argument("domain", help="a root domain to start enum with")
parser.add_argument("-d", "--debug", action="store_true", help="show timings")
parser.add_argument("-s", "--skip-scraping", action="store_true", help="skip amass and subfinder")
parser.add_argument("-b", "--skip-brutforcing", action="store_true", help="skip brute-forcing domain names with massdns")
parser.add_argument("-cc", "--skip-censys", action="store_true", help="skip censys certificates search for new hosts")
parser.add_argument("-sp", "--skip-portscanning", action="store_true", help="skip scanning ports of found hosts")
parser.add_argument("-c", "--company-name", action="append", help="company name to search through ASNs")
args = parser.parse_args()
show_time("program started")
subdoamins_found = []
ip_addresses = {}
asns_in_scope = []

if args.company_name is not None:
	search_asn_thread = Thread(target=search_asns, args=(args.company_name,))
	search_asn_thread.start()

if not args.skip_scraping:
	amass_thread = Thread(target=search_subdomains_with_amass, args=(args.domain,))
	subfinder_thread = Thread(target=search_subdomains_with_subfinder, args=(args.domain,))

	amass_thread.start()
	subfinder_thread.start()

	amass_thread.join()
	subfinder_thread.join()

	resolve_subdomains_from_scraping()

if not args.skip_brutforcing:
	brute_subdomains_with_massdns(args.domain)

if not args.skip_brutforcing or not args.skip_scraping:
	resolve_cnames()
	inter = 0
	for target in subdoamins_found:
		if 'ip' in target:
			for ip in target['ip']:
				if ip not in ip_addresses:
					inter = inter + 1
					ip_addresses[ip] = { 'source' : "subdomains searching" }
	print(inter, " ip addressess found from subdomains searching")

if args.company_name is not None:
	search_asn_thread.join()
	inter = 0
	for asn in asns_in_scope:
		ips = IPNetwork(asn)
		for address in ips:
			addr = str(address)
			if addr not in ip_addresses:
				inter = inter + 1
				ip_addresses[addr] = { 'source' : "ASNs searching" }
	print(inter, " ip addressess found from ASNs searching")

if not args.skip_censys:
	censys_addressess = search_through_censys_for_new_hosts(args.domain)
	inter = 0
	for host in censys_addressess:
		if host not in ip_addresses:
			inter = inter + 1
			ip_addresses[host] = { 'source' : "certificates search through censys" }
	print(inter, " ip addressess found from search through certificates on censys")

if not args.skip_portscanning:
	scan_ports_of_target_hosts()

print(json.dumps(ip_addresses, indent = 4))
print(len(subdoamins_found))
print(*subdoamins_found, sep='\n')

time_finished = datetime.now()
if args.debug:
	print("It took: ", time_finished - time_started)