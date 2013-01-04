##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary

	# Exploit mixins should be called first
	include Msf::Exploit::Remote::SMB
	include Msf::Exploit::Remote::SMB::Authenticated

	include Msf::Exploit::Remote::DCERPC

	# Scanner mixin should be near last
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::Scanner

	def initialize
		super(
			'Name'        => 'SMB Share Enumeration',
			'Description' => 'Determine what shares are provided by the SMB service',
			'Author'      => 'hdm',
			'License'     => MSF_LICENSE,
			'DefaultOptions' => {
				'DCERPC::fake_bind_multi' => false
			}
		)

		register_advanced_options(
			[
				OptBool.new('USE_SRVSVC_ONLY', [true, "By default a netshareenum request is done on the lanman pipe and if fails a second try is done on srvsvc", false])
			], self.class)

		deregister_options('RPORT', 'RHOST')
	end

	def share_type(val)
		stypes = [
			'DISK',
			'PRINTER',
			'DEVICE',
			'IPC',
			'SPECIAL',
			'TEMPORARY'
		]

		if val > (stypes.length - 1)
			return 'UNKNOWN'
		end

		stypes[val]
	end

	def lanman_netshareenum
		begin
		res = self.simple.client.trans(
			"\\PIPE\\LANMAN",
			(
				[0x00].pack('v') +
				"WrLeh\x00"   +
				"B13BWz\x00"  +
				[0x01, 65406].pack("vv")
			)
		)
		rescue ::Rex::Proto::SMB::Exceptions::ErrorCode => e
			#STATUS_NOT_SUPPORTED
			if( e.error_code == 0xC00000BB )
				srvsvc_netshareenum
				return
			end
		end
		return if res.nil?

		lerror, lconv, lentries, lcount = res['Payload'].to_s[
			res['Payload'].v['ParamOffset'],
			res['Payload'].v['ParamCount']
		].unpack("v4")

		data = res['Payload'].to_s[
			res['Payload'].v['DataOffset'],
			res['Payload'].v['DataCount']
		]

		0.upto(lentries - 1) do |i|
			sname,tmp = data[(i * 20) +  0, 14].split("\x00")
			stype     = data[(i * 20) + 14, 2].unpack('v')[0]
			scoff     = data[(i * 20) + 16, 2].unpack('v')[0]
			if ( lconv != 0)
				scoff -= lconv
			end
			scomm,tmp = data[scoff, data.length - scoff].split("\x00")

			@shares << [ sname, share_type(stype), scomm]
		end
	end

	def srvsvc_netshareenum

		simple.connect("\\\\#{rhost}\\IPC$")
		handle = dcerpc_handle('4b324fc8-1670-01d3-1278-5a47bf6ee188', '3.0', 'ncacn_np', ["\\srvsvc"])
		begin
			dcerpc_bind(handle)
		rescue Rex::Proto::SMB::Exceptions::ErrorCode => e
			print_error("#{rhost} : #{e.message}")
			return
		end

		stubdata =
			NDR.uwstring("\\\\#{rhost}") +
			NDR.long(1)  #level

		ref_id = stubdata[0,4].unpack("V")[0]
		ctr = [1, ref_id + 4 , 0, 0].pack("VVVV")

		stubdata << ctr
		stubdata << NDR.align(ctr)
		stubdata << ["FFFFFFFF"].pack("H*")
		stubdata << [ref_id + 8, 0].pack("VV")
		response = dcerpc.call(0x0f, stubdata)
		res = response.dup
		win_error = res.slice!(-4, 4).unpack("V")[0]
		if win_error != 0
			raise "DCE/RPC error : Win_error = #{win_error + 0}"
		end
		#remove some uneeded data
		res.slice!(0,12) # level, CTR header, Reference ID of CTR
		share_count = res.slice!(0, 4).unpack("V")[0]
		res.slice!(0,4) # Reference ID of CTR1
		share_max_count = res.slice!(0, 4).unpack("V")[0]

		raise "Dce/RPC error : Unknow situation encountered count != count max (#{share_count}/#{share_max_count})" if share_max_count != share_count

		types = res.slice!(0, share_count * 12).scan(/.{12}/n).map{|a| a[4,2].unpack("v")[0]}  # RerenceID / Type / ReferenceID of Comment

		share_count.times do |t|
			length, offset, max_length = res.slice!(0, 12).unpack("VVV")
			raise "Dce/RPC error : Unknow situation encountered offset != 0 (#{offset})" if offset != 0
			raise "Dce/RPC error : Unknow situation encountered length !=max_length (#{length}/#{max_length})" if length != max_length
			name = res.slice!(0, 2 * length).gsub('\x00','')
			res.slice!(0,2) if length % 2 == 1 # pad

			comment_length, comment_offset, comment_max_length = res.slice!(0, 12).unpack("VVV")
			raise "Dce/RPC error : Unknow situation encountered comment_offset != 0 (#{comment_offset})" if comment_offset != 0
			if comment_length != comment_max_length
				raise "Dce/RPC error : Unknow situation encountered comment_length != comment_max_length (#{comment_length}/#{comment_max_length})"
			end
			comment = res.slice!(0, 2 * comment_length).gsub('\x00','')
			res.slice!(0,2) if comment_length % 2 == 1 # pad

			@shares << [ name, share_type(types[t]), comment]
		end
	end

	def run_host(ip)

		@shares = []

		[[139, false], [445, true]].each do |info|
			datastore['RPORT'] = info[0]
			datastore['SMBDirect'] = info[1]

			begin
				connect
				smb_login
				if datastore['USE_SRVSVC_ONLY']
					srvsvc_netshareenum
				else
					#If not implemented by target, will fall back to srvsvc_netshareenum
					lanman_netshareenum
				end

				if not @shares.empty?
					print_status("#{ip}:#{rport} #{@shares.map{|x| "#{x[0]} - #{x[2]} (#{x[1]})" }.join(", ")}")
					report_note(
						:host => ip,
						:proto => 'tcp',
						:port => rport,
						:type => 'smb.shares',
						:data => { :shares => @shares },
						:update => :unique_data
					)
				end

				disconnect
				return
			rescue ::Timeout::Error
			rescue ::Interrupt
				raise $!
			rescue ::Rex::ConnectionError
			rescue ::Rex::Proto::SMB::Exceptions::LoginError
				next
			rescue ::Exception => e
				print_line("Error: #{ip} #{e.class} #{e}")
			end
		end
	end


end
