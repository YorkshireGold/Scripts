
require 'json'

=begin
BG: I had some issues with dependency check recently, so I wrote a parser for trivy's output.  you can use it as follows:
$ trivy fs -f json -o trivy.json . 
$ ruby parse_trivy_json.rb trivy.json

=end

parsed = JSON.parse(IO.readlines(ARGV[0]).join(''))
official_cves_only = !ARGV[1].nil?
omit_from = !ARGV[2].nil?

parsed.each do |target|
	next unless target["Vulnerabilities"]
	src = target["Target"]
	target["Vulnerabilities"].each do |vuln|
		pkg = vuln["PkgName"]
		cve = vuln["VulnerabilityID"]
		should_report = !official_cves_only 	
		if cve =~ /CVE.*/
			should_report = true
		end


		desc = vuln["Title"] + " : " + vuln["Description"]
		sev = vuln["Severity"]
		if vuln["CVSS"]
			cvss = "(#{vuln["CVSS"]["nvd"]["V3Score"]}) #{vuln["CVSS"]["nvd"]["V3Vector"]}"
		else
			cvss = ""
		end

	
		ref = vuln["References"].first

		if should_report
			puts "-"*50
			puts pkg
			puts "from: #{src}" if !omit_from
			puts "CVE: #{cve} #{cvss}"
			puts desc
			puts ref
		end

	end
end


