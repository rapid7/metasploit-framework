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

class Metasploit3 < Msf::Auxiliary

	include Msf::Auxiliary::Scanner
	include Msf::Exploit::Remote::Tcp

	def initialize
		super(
			'Name'           => 'Simple FTP Fuzzer',
			'Description'    => %q{
				This module will connect to a FTP server and perform pre- and post-authentication fuzzing
			},
			'Author'         => [ 'corelanc0d3r', 'jduck' ],
			'License'        => MSF_LICENSE,
			'Version'        => '$Revision$'
			)

		register_options(
			[
				Opt::RPORT(21),
				OptInt.new('STARTATSTAGE', [ false, "Start at this test stage",1]),
				OptInt.new('STEPSIZE', [ false, "Increase string size each iteration with this number of chars",10]),
				OptInt.new('DELAY', [ false, "Delay between connections",0.5]),
				OptInt.new('STARTSIZE', [ false, "Fuzzing string startsize",10]),
				OptInt.new('ENDSIZE', [ false, "Fuzzing string endsize",20000]),
				OptString.new('USER', [ false, "Username",'anonymous']),
				OptString.new('PASS', [ false, "Password",'anonymous@test.com'])
			], self.class)
		deregister_options('RHOST')

		@evilchars = [
			'A','a','%s','%d','%n','%x','%p','-1','0','0xfffffffe','0xffffffff','A/','//','/..','//..',
			'A%20','./A','.A',',A','A:','!A','&A','?A','\A','../A/','..?','//A:','\\A','{A','$A','A*',
			'cmd','A@a.com','#A','A/../','~','~A','~A/','A`/','>A','<A','A%n','A../','.././','A../',
			'....//','~?*/','.\../','\.//A','-%A','%Y','%H','/1','!','@','%','&','/?(*','*','(',')',
			'`',',','~/','/.','\$:','/A~%n','=','=:;)}','1.2.','41414141','-1234','999999,','%00','+A',
			'+123','..\'','??.','..\.\'','.../','1234123+',
			'%Y%%Y%/','%FC%80%80%80%80%AE%FC%80%80%80%80%AE/','????/','\uff0e/','%%32%65%%32%65/',
			'+B./','%%32%65%%32%65/','..%c0%af','..%e0%80%af','..%c1%9c'
		]
		@commands = [
			'ABOR','ACCT','ALLO','APPE','AUTH','CWD','CDUP','DELE','FEAT','HELP','HOST','LANG','LIST',
			'MDTM','MKD','MLST','MODE','NLST','NLST -al','NOOP','OPTS','PASV','PORT','PROT','PWD','REIN',
			'REST','RETR','RMD','RNFR','RNTO','SIZE','SITE','SITE CHMOD','SITE CHOWN','SITE EXEC','SITE MSG',
			'SITE PSWD','SITE ZONE','SITE WHO','SMNT','STAT','STOR','STOU','STRU','SYST','TYPE','XCUP',
			'XCRC','XCWD','XMKD','XPWD','XRMD'
		]
		@emax = @evilchars.length
	end


	def get_pkt
		buf = sock.get
		print_status("[in ] #{buf.inspect}") if datastore['VERBOSE']
		buf
	end

	def send_pkt(pkt, get_resp = false)
		print_status("[out] #{pkt.inspect}") if datastore['VERBOSE']
		sock.put(pkt)
		get_pkt if get_resp
	end


	def process_phase(phase_num, phase_name, prepend = '', initial_cmds = [])
		print_status("[Phase #{phase_num}] #{phase_name} - #{Time.now.localtime}")
		ecount = 1
		@evilchars.each do |evilstr|
			count = datastore['STARTSIZE']
			print_status(" Character : #{evilstr} (#{ecount}/#{@emax})")
			ecount += 1
			while count < datastore['ENDSIZE']
				begin
					connect
					print_status("  -> Fuzzing size set to #{count}")
					evil = evilstr * count
					initial_cmds.each do |cmd|
						send_pkt(cmd, true)
					end
					pkt = prepend + evil + "\n"
					send_pkt(pkt, true)
					sock.put("QUIT\n")
					select(nil, nil, nil, datastore['DELAY'])
					disconnect

					count += datastore['STEPSIZE']

				rescue ::Exception => e
					if (e.class.name == 'Rex::ConnectionRefused') or (e.class.name == 'EOFError') or (e.class.name == 'Errno::ECONNRESET') or (e.class.name == 'Errno::EPIPE')
						print_status("Crash string : #{prepend}#{evilstr} x #{count}")
						print_status("System does not respond - exiting now\n")
						return
					end
					print_error("Error: #{e.class} #{e} #{e.backtrace}\n")
				end
			end
		end
	end


	def run_host(ip)

		startstage = datastore['STARTATSTAGE']

		print_status("Connecting to host " + ip + " on port " + datastore['RPORT'])

		if (startstage == 1)
			process_phase(1, "Fuzzing without command")
			startstage += 1
		end

		if (startstage == 2)
			process_phase(2, "Fuzzing USER", 'USER ')
			startstage += 1
		end

		if (startstage == 3)
			process_phase(3, "Fuzzing PASS", 'PASS ',
				[ "USER " + datastore['USER'] + "\n" ])
			startstage += 1
		end

		if (startstage == 4)
			@commands.each do |cmd|
				process_phase(4, "Fuzzing command: #{cmd}", "#{cmd} ",
					[
						"USER " + datastore['USER'] + "\n",
						"PASS " + datastore['PASS'] + "\n"
					])
			end
			# Don't progress into stage 5, it must be selected manually.
			#startstage += 1
		end

		# Fuzz other commands, all command combinations in one session
		if startstage == 5
			print_status("[Phase 5] Fuzzing other commands - Part 2 - #{Time.now.localtime}")
			@commands.each do |cmd|
				ecount = 1
				count = datastore['STARTSIZE']
				print_status("Fuzzing command #{cmd} - #{Time.now.localtime}" )

				connect
				pkt = "USER " + datastore['USER'] + "\n"
				send_pkt(pkt, true)
				pkt = "PASS " + datastore['PASS'] + "\n"
				send_pkt(pkt, true)

				while count < datastore['ENDSIZE']
					print_status("  -> Fuzzing size set to #{count}")
					begin
						@evilchars.each do |evilstr|
							print_status(" Character : #{evilstr} (#{ecount}/#{@emax})")
							ecount += 1
							evil = evilstr * count
							pkt = cmd + " " + evil + "\n"
							send_pkt(pkt, true)
							select(nil, nil, nil, datastore['DELAY'])
						end
					rescue ::Exception => e
						if (e.class.name == 'Rex::ConnectionRefused') or (e.class.name == 'EOFError') or (e.class.name == 'Errno::ECONNRESET') or (e.class.name == 'Errno::EPIPE')
							print_status("Crash string : #{cmd} #{evilchr} x #{count}")
							print_status("System does not respond - exiting now\n")
							return
						end
						print_error("Error: #{e.class} #{e} #{e.backtrace}\n")
					end
					count += datastore['STEPSIZE']
				end
				sock.put("QUIT\n")
				select(nil, nil, nil, datastore['DELAY'])
				disconnect
			end
		end
	end

end
