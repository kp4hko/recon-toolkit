import argparse
import subprocess
from datetime import datetime
from threading import Thread
import re
import json

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
	unique_names, _ = execute_massdns(list_of_subdomains_to_test)
	show_time("brute-forcing subdomains finished")
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

time_started = datetime.now()
parser = argparse.ArgumentParser()
parser.add_argument("domain", help="a root domain to start enum with")
parser.add_argument("-d", "--debug", action="store_true", help="show timings")
parser.add_argument("-s", "--skip-scraping", action="store_true", help="skip amass and subfinder")
parser.add_argument("-b", "--skip-brutforcing", action="store_true", help="skip brute-forcing domain names with massdns")
args = parser.parse_args()
show_time("program started")
subdoamins_found = []
ip_addresses = {}

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

print(len(subdoamins_found))
print(*subdoamins_found, sep='\n')

time_finished = datetime.now()
if args.debug:
	print("It took: ", time_finished - time_started)