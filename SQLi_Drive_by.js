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
	"A syntax error has occurred",
	"Active Server Pages error",
	"ADODB.Field error",
	"An illegal character has been found in the statement",
	"An unexpected token .* was found",
	"ASP\.NET is configured to show verbose error messages",
	"ASP\.NET_SessionId",
	"Custom Error Message",
	"database error",
	"DB2 Driver",
	"DB2 Error",
	"DB2 ODBC",
	"detected an internal error",
	"Error converting data type varchar to numeric",
	"Error Diagnostic Information",
	"Error Report",
	"Fatal error",
	"Incorrect syntax near",
	"Index of",
	"Internal Server Error",
	"Invalid Path Character",
	"Invalid procedure call or argument",
	"invalid query",
	"Invision Power Board Database Error",
	"is not allowed to access",
	"JDBC Driver",
	"JDBC Error",
	"JDBC MySQL",
	"JDBC Oracle",
	"JDBC SQL",
	"Microsoft OLE DB Provider for ODBC Drivers",
	"Microsoft VBScript compilation error",
	"Microsoft VBScript error",
	"MySQL Driver",
	"mysql error",
	"MySQL Error",
	"mySQL error with query",
	"MySQL ODBC",
	"ODBC DB2",
	"ODBC Driver",
	"ODBC Error",
	"ODBC Microsoft Access",
	"ODBC Oracle",
	"ODBC SQL",
	"OLE/DB provider returned message",
	"on line",
	"on MySQL result index",
	"Oracle DB2",
	"Oracle Driver",
	"Oracle Error",
	"Oracle ODBC",
	"Parent Directory",
	"PHP Error",
	"Invalid email or password",
	"PHP Parse error",
	"PHP Warning",
	"PostgreSQL query failed",
	"server object error",
	"SQL command not properly ended",
	"SQL Server Driver",
	"SQL error",
	"SQL ",
	"SQLException",
	"supplied argument is not a valid",
	"Syntax error in query expression",
	"The error occurred in",
	"The script whose uid is",
	"Type mismatch",
	"Unable to jump to row",
	"Unclosed quotation mark before the character string",
	"unexpected end of SQL command",
	"unexpected error",
	"Unterminated string constant",
	"Warning: mysql_query",
	"Warning: pg_connect",
	"You have an error in your SQL syntax near",
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
	as.raiseAlert(3, 3,'---- WALK AROUND : SQLi ----', evidence ,msg.getRequestHeader().getURI().toString(), param, attack, '', '', evidence, 0, 0, msg)
}
