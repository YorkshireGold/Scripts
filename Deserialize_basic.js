/*
 This script is to find Deserization activity based on response content.
 The script is to be used in ActiveScan mode as you "drive by"
 */

var attacks = [
	"`",
	";",
	"'",
]

// List beneath of potential error messages that could be found Serializtion activity - needs reviseing to inlcude other languages
var evidence = [
	"Deserialised",
	"Deserialized",
	"Deserializable",
	"serialised",
	"serialized",
	"serialise",
	"serialisable",
	"serialize",
	"serializable",
	"Serialization",
	"Deserialization",
	"node-serialize",			// name of a sensitive Node package that might allow for it
	"serialize-to-js",			// another sensitive Node package that might allow for it
	"rO0",					// a java Deserilisation signature string
	"x-java-serialized-object",	
]

function scan(as, msg, param, value) {
	for (i = 0; i < attacks.length; i++) {
		new_msg = msg.cloneRequest();
		attack1 = attacks[i]
		as.setParam(new_msg, param, value + attack1);
		as.sendAndReceive(new_msg, false, false);
		var Responsebody = new_msg.getResponseBody().toString()
		var re = new RegExp(evidence.join("|"), "i")
		var found = Responsebody.match(re)
		StatusCode = new_msg.getResponseHeader().getStatusCode()
		Header = new_msg.getResponseHeader().getHeadersAsString()
		Header = new_msg.getResponseHeader().toString()
		HeaderAndBody = Header + Responsebody
		var found = HeaderAndBody.match(re)
		if (found!=null) {	// Change to a test which detects the vulnerability
			// NewFound = 'Code -> : ' + new_msg.getResponseHeader().getStatusCode() + ' |     -> ' + new_msg.getRequestHeader().getURI().toString() +'    |--> found string in response --> ' + found + ' Time: ' + msg.getTimeSentMillis().toString()
			print("------------------------------------------")
			raiseAlert(as, new_msg, param, attacks[i], NewFound)
			
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
	as.raiseAlert(3, 3,'- WALK AROUND : Deserialize ----', evidence ,msg.getRequestHeader().getURI().toString(), param, attack, '', '', evidence, 0, 0, msg)
}
}
