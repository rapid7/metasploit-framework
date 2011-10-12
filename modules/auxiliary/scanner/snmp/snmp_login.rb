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
require 'snmp'

class Metasploit3 < Msf::Auxiliary

	include Msf::Auxiliary::Report
	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::AuthBrute

	def initialize
		super(
			'Name'        => 'SNMP Community Scanner',
			'Version'     => '$Revision$',
			'Description' => 'Scan for SNMP devices using common community names',
			'Author'      => 'hdm',
			'References'     =>
				[
					[ 'CVE', '1999-0508'] # Weak password
				],
			'License'     => MSF_LICENSE
		)

		register_options(
		[
			Opt::RPORT(161),
			Opt::CHOST,
			OptInt.new('BATCHSIZE', [true, 'The number of hosts to probe in each set', 256]),
			OptString.new('PASSWORD', [ false, 'The password to test' ]),
			OptPath.new('PASS_FILE',  [ false, "File containing communities, one per line",
				File.join(Msf::Config.install_root, "data", "wordlists", "snmp_default_pass.txt")
			])
		], self.class)

		deregister_options('USERNAME', 'USER_FILE', 'USERPASS_FILE')
	end


	# Define our batch size
	def run_batch_size
		datastore['BATCHSIZE'].to_i
	end

	# Operate on an entire batch of hosts at once
	def run_batch(batch)

		@found = {}
		@tried = []

		begin
			udp_sock = nil
			idx = 0

			# Create an unbound UDP socket if no CHOST is specified, otherwise
			# create a UDP socket bound to CHOST (in order to avail of pivoting)
			udp_sock = Rex::Socket::Udp.create( { 'LocalHost' => datastore['CHOST'] || nil, 'Context' => {'Msf' => framework, 'MsfExploit' => self} })
			add_socket(udp_sock)

			each_user_pass do |user, pass|
				comm = pass

				data1 = create_probe_snmp1(comm)
				data2 = create_probe_snmp2(comm)

				batch.each do |ip|
					fq_pass = [ip,pass]
					next if @tried.include? fq_pass
					@tried << fq_pass
					print_status "#{ip}:#{datastore['RPORT']} - SNMP - Trying #{(pass.nil? || pass.empty?) ? "<BLANK>" : pass}..." if datastore['VERBOSE']

					begin
						udp_sock.sendto(data1, ip, datastore['RPORT'].to_i, 0)
						udp_sock.sendto(data2, ip, datastore['RPORT'].to_i, 0)
					rescue ::Interrupt
						raise $!
					rescue ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionRefused
						nil
					end

					if (idx % 10 == 0)
						while (r = udp_sock.recvfrom(65535, 0.25) and r[1])
							parse_reply(r)
						end
					end
					
					idx += 1

				end
			end

			idx = 0
			while (r = udp_sock.recvfrom(65535, 3) and r[1] and idx < 500)
				parse_reply(r)
				idx += 1
			end

			if @found.keys.length > 0
				print_status("Validating scan results from #{@found.keys.length} hosts...")
			end

			# Review all successful communities and determine write access
			@found.keys.sort.each do |host|
				fake_comm  = Rex::Text.rand_text_alphanumeric(8)
				anycomm_ro = false
				anycomm_rw = false
				comms_ro   = []
				comms_rw   = []
				finished   = false
				versions = ["1", "2"]

				versions.each do |version|
				comms_todo = @found[host].keys.sort
				comms_todo.unshift(fake_comm)

				comms_todo.each do |comm|
					begin
						sval = nil
						snmp = snmp_client(host, datastore['RPORT'].to_i, version, udp_sock, comm)
						resp = snmp.get("sysName.0")
						resp.each_varbind { |var| sval = var.value }
						next if not sval

						svar = ::SNMP::VarBind.new("1.3.6.1.2.1.1.5.0", ::SNMP::OctetString.new(sval))
						resp = snmp.set(svar)

						if resp.error_status == :noError
							comms_rw << comm
							print_status("Host #{host} provides READ-WRITE access with community '#{comm}'")
							if comm == fake_comm
								anycomm_rw = true
								finished   = true
								break
							end
						else
							comms_ro << comm
							print_status("Host #{host} provides READ-ONLY access with community '#{comm}'")
							if comm == fake_comm
								anycomm_ro = true
								finished   = true
								break
							end
						end

						# Used to flag whether this version was compatible
						finished = true

					rescue ::SNMP::UnsupportedPduTag, ::SNMP::InvalidPduTag, ::SNMP::ParseError, ::SNMP::InvalidErrorStatus, ::SNMP::InvalidTrapVarbind, ::SNMP::InvalidGenericTrap, ::SNMP::BER::OutOfData, ::SNMP::BER::InvalidLength, ::SNMP::BER::InvalidTag, ::SNMP::BER::InvalidObjectId, ::SNMP::MIB::ModuleNotLoadedError, ::SNMP::UnsupportedValueTag
						next

					rescue ::SNMP::UnsupportedVersion
						break
					rescue ::SNMP::RequestTimeout
						next
					end
				end

				break if finished
				end

				# Report on the results
				comms_ro = ["anything"] if anycomm_ro
				comms_rw = ["anything"] if anycomm_rw

				comms_rw.each do |comm|
					report_auth_info(
						:host   => host,
						:port   => datastore['RPORT'].to_i,
						:proto  => 'udp',
						:sname  => 'snmp',
						:user   => '',
						:pass   => comm,
						:duplicate_ok => true,
						:active => true,
						:type   => "password"
					)
				end

				comms_ro.each do |comm|
					report_auth_info(
						:host   => host,
						:port   => datastore['RPORT'].to_i,
						:proto  => 'udp',
						:sname  => 'snmp',
						:user   => '',
						:pass   => comm,
						:duplicate_ok => true,
						:active => true,
						:type   => "password_ro"
					)
				end
			end

		rescue ::Interrupt
			raise $!
		rescue ::Exception => e
			print_error("Unknown error: #{e.class} #{e}")
		end

	end

	#
	# Allocate a SNMP client using the existing socket
	#
	def snmp_client(host, port, version, socket, community)
		version = :SNMPv1  if version == "1"
		version = :SNMPv2c if version == "2c"

		snmp = ::SNMP::Manager.new(
			:Host      => host,
			:Port      => port,
			:Community => community,
			:Version => version,
			:Timeout => 1,
			:Retries => 2,
			:Transport => SNMP::RexUDPTransport,
			:Socket => socket
		)
	end

	#
	# The response parsers
	#
	def parse_reply(pkt)

		return if not pkt[1]

		if(pkt[1] =~ /^::ffff:/)
			pkt[1] = pkt[1].sub(/^::ffff:/, '')
		end

		asn = ASNData.new(pkt[0])
		inf = asn.access("L0.L0.L0.L0.V1.value")
		if (inf)
			inf.gsub!(/\r|\n/, ' ')
			inf.gsub!(/\s+/, ' ')
		end

		com = asn.access("L0.V1.value")
		if(com)
			@found[pkt[1]]||={}
			if(not @found[pkt[1]][com])
				print_good("SNMP: #{pkt[1]} community string: '#{com}' info: '#{inf}'")
				@found[pkt[1]][com] = inf
			end

			report_service(
				:host   => pkt[1],
				:port   => pkt[2],
				:proto  => 'udp',
				:name  => 'snmp',
				:info   => inf,
				:state => "open"
			)
		end
	end


	def create_probe_snmp1(name)
		xid = rand(0x100000000)
		pdu =
			"\x02\x01\x00" +
			"\x04" + [name.length].pack('c') + name +
			"\xa0\x1c" +
			"\x02\x04" + [xid].pack('N') +
			"\x02\x01\x00" +
			"\x02\x01\x00" +
			"\x30\x0e\x30\x0c\x06\x08\x2b\x06\x01\x02\x01" +
			"\x01\x01\x00\x05\x00"
		head = "\x30" + [pdu.length].pack('C')
		data = head + pdu
		data
	end

	def create_probe_snmp2(name)
		xid = rand(0x100000000)
		pdu =
			"\x02\x01\x01" +
			"\x04" + [name.length].pack('c') + name +
			"\xa1\x19" +
			"\x02\x04" + [xid].pack('N') +
			"\x02\x01\x00" +
			"\x02\x01\x00" +
			"\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01" +
			"\x05\x00"
		head = "\x30" + [pdu.length].pack('C')
		data = head + pdu
		data
	end


	#
	# Parse a asn1 buffer into a hash tree
	#

	class ASNData < ::Hash

		def initialize(data)
			_parse_asn1(data, self)
		end

		def _parse_asn1(data, tree)
			x = 0
			while (data.length > 0)
				t,l = data[0,2].unpack('CC')
				i = 2

				if (l > 0x7f)
					lb = l - 0x80
					l = (("\x00" * (4-lb)) + data[i, lb]).unpack('N')[0]
					i += lb
				end

				buff = data[i, l]

				tree[:v] ||= []
				tree[:l] ||= []
				case t
					when 0x00...0x29
						tree[:v] << [t, buff]
					else
						tree[:l][x] ||= ASNData.new(buff)
						x += 1
				end
				data = data[i + l, data.length - l]
			end
		end

		def access(desc)
			path = desc.split('.')
			node = self
			path.each_index do |i|
				case path[i]
					when /^V(\d+)$/
						if (node[:v] and node[:v][$1.to_i])
							node = node[:v][$1.to_i]
							next
						else
							return nil
						end
					when /^L(\d+)$/
						if (node[:l] and node[:l][$1.to_i])
							node = node[:l][$1.to_i]
							next
						else
							return nil
						end
					when 'type'
						return (node and node[0]) ? node[0] : nil
					when 'value'
						return (node and node[1]) ? node[1] : nil
					else
						return nil
				end
			end
			return node
		end
	end



end

