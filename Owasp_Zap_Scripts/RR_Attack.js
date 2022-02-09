function bigPayload() {
		var res='Geoff';
		for(var i=0;i<6144;i++)  res+='A'; 
		return res;
	}

var attacks = [
	//"&Geoff",
	//"&&Geoff",
	//"|Geoff",
	bigPayload(),
	//"\'--",
	"*",
	"%00",
	"\r\n"
]

function scan(as, msg, param, value) {
	var i;
	var originalURI = msg.getRequestHeader().getURI().getEscapedPath().toString();  //want the original URL
	for (i = 0; i < attacks.length; i++) {
		msg = msg.cloneRequest();
		print('OSi attackVector: ' + value + attacks[i]);
		as.setParam(msg, param, value + attacks[i]);
		as.sendAndReceive(msg, false, false);
		
		// work with response and set some variables for alert
		// https://www.zaproxy.org/blog/2021-02-10-automate-checking-asvs-controls-using-zap-scripts/
		var strHTTPResponse = msg.getResponseBody().toString();
		var alertDescription = strHTTPResponse;
		var alertURI = msg.getRequestHeader().getURI().getEscapedPath().toString();
		var alertParam = param;
		var alertAttack = attacks[i];
		var alertOther = msg.getResponseHeader();
		var alertSolution = "NA";
		var alertEvidence = strHTTPResponse.match(/(exception|syntax|application.error|unexpected.error)/i);
		var alertName = alertEvidence + " String Found";
		if( alertEvidence != null)
		{
			//print(strHTTPResponse.search(/(exception|syntax)/i));
			print('HIT - attackVector: ' + value + attacks[i] + ' || parameter: ' + param + ' || evidence: ' + alertEvidence);
			as.raiseAlert(1,1,alertName,alertDescription,originalURI,alertParam,alertAttack,alertOther,alertURI,alertEvidence,0,0,msg);
		}
	}
}
