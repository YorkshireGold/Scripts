/*
 This script is to find SQLi based on error messages in responses are sending a malicious attack string in a parameter.
 The script is to be used in ActiveScan mode as you "drive by"
 */

var attacks = [
	"`",
	";",
	"'",
	"`--",
	"'--",
	";--",
     "#",
]

// List beneath of potential error messages that could be found in SQL error messages
var evidence = [
	"Deserialised",
	"serialised",
	"serialized",
	"Deserialised",
	"rO0",
]

function scan(as, msg, param, value) {
	for (i = 0; i < attacks.length; i++) {
		new_msg = msg.cloneRequest();
		intRandom = Math.floor((Math.random() * 9999) + 1);
		attack1 = attacks[i]
		as.setParam(new_msg, param, value + attack1);
		as.sendAndReceive(new_msg, false, false);
		// Add any generic checks here, eg
	
		var body = new_msg.getResponseBody().toString()
		
		var re = new RegExp(evidence.join("|"), "i")
		//print(body)
		var found = body.match(re)
		StatusCode = new_msg.getResponseHeader().getStatusCode()
		Header = new_msg.getResponseHeader().getHeadersAsString()
		Header = new_msg.getResponseHeader().toString()
		HeaderAndBody = Header + body
		var found = HeaderAndBody.match(re)
		// print(HeaderAndBody)   // This wiwll print all the content of the response. Good for debugging
		if (found!=null && StatusCode == (200 || 301 || 302 || 408 ) || (StatusCode > 500 )) {	// Change to a test which detects the vulnerability
			NewFound = 'Code -> : ' + new_msg.getResponseHeader().getStatusCode() + ' |     -> ' + new_msg.getRequestHeader().getURI().toString() +'    |--> found string in response --> ' + found + ' Time: ' + msg.getTimeSentMillis().toString()
			print("------------------------------------------")
			print(NewFound)
			raiseAlert(as, new_msg, param, attacks[i], NewFound)
			
			// Only raise one alert per param
			return 0
		}

	}

	// Replace with more suitable information
	// raiseAlert(risk, int confidence, String name, String description, String uri, 
	//		String param, String attack, String otherInfo, String solution, String evidence, 
	//		int cweId, int wascId, HttpMessage msg)
	// risk: 0: info, 1: low, 2: medium, 3: high
	// confidence: 0: falsePositive, 1: low, 2: medium, 3: high, 4: confirmed

function raiseAlert(as, msg, param, attack, evidence) {
	as.raiseAlert(3, 3,'---- WALK AROUND : Deserialize ----', evidence ,msg.getRequestHeader().getURI().toString(), param, attack, '', '', evidence, 0, 0, msg)
}
}
