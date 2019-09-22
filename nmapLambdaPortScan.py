#python3
import timeit
import nmap
import sys
import socket
import json
import requests


def Send2Slack(message):

	webhook_url = 'https://hooks.slack.com/services/7HHJ9YHJJ/8JJHN7GNMMN/r1l6ue8JKJY8JcAnhgjheWrYJ'
	slack_data = {'text': str(message)}

	response = requests.post(
		webhook_url, data=json.dumps(slack_data),
		headers={'Content-Type': 'application/json'}
	)
	if response.status_code != 200:
		raise ValueError(
			'Request to slack returned an error %s, the response is:\n%s'
			% (response.status_code, response.text)
		)

def scan(scanhost):
	host = ""
	output = ""
	tic = timeit.default_timer()
	message = ("Port scan of " + scanhost + " begining...\n")
	Send2Slack(message)
	nm = nmap.PortScanner()
	nm.scan(scanhost, arguments='-sT')
	for host in nm.all_hosts():
		output += ('Host : %s (%s)\n' % (host, nm[host].hostname()))
		output += ('State : %s\n' % nm[host].state())
		for proto in nm[host].all_protocols():
			print(nm[host])
			output += ('----------\n')
			output += ('Protocol : %s\n' % proto)
			lport = nm[host][proto].keys()
			for port in lport:
				output += ('port : %s \tstate : %s \n' % (port, nm[host][proto][port]['state']))
	toc =  timeit.default_timer()
	sumt = toc - tic
	sumt = ("{0:.2f}".format(round(sumt,2)))
	if output:
		output += "\nTime taken to scan host " + host + ": " + str(sumt) + " seconds\n"
		print('%s' % (output))
		Send2Slack(output)

def lambdaHandler(event, context):
	#We need to pull the external address of the hostname to be port scanned from the AWS event.
	scan(hostArg)
	
def scanWrapper():
	for arg in sys.argv[1:]:
		error = None
		try:
			scanhost = socket.gethostbyname(arg)
		except socket.gaierror:
			error = "Hostname: %s could not be resolved. Does the host exist? Exiting" % arg
			Send2Slack(error)
		except socket.error:
			error = "Couldn't connect to server"
			Send2Slack(error)
		if not error:
			for arg in sys.argv[1:]:
				scan(arg)
	
def main ():
	if (len(sys.argv) < 2):
		print('Usage: %s host [host]...' % sys.argv[0])
		sys.exit()
	scanWrapper()

main()
