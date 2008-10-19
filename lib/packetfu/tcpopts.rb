
module PacketFu

	# TcpOpts handles the translation of TCP option strings to human-readable form,
	# and vice versa. It is nearly certain to be completely rewritten, though the
	# syntax will remain the same.
	#
	# == Example
	#
	#   tcp_pkt = PacketFu::TCPPacket.new
	#   tcp_pkt.tcp_options="nop,nop,sack.ok,ws:7,eol"
	#
	# It's usable now, but you should not trust attacker data, since certain
	# combinations of malformed options will raise execeptions.
	#
	# See http://www.iana.org/assignments/tcp-parameters/ for the rules on sizes and such.
	class TcpOpts
		include Singleton
	
		# XXX: Here be dragons!
		#
		# Like decode, encode requires fairly strict adherance to the various
		# RFCs when it comes to lengths and expected data types. If you're
		# trying to enter well-formed data, it should all work fine. If you're
		# trying to something like fuzzing, then you'll probably have better
		# luck using tcp_opts= instead.
		#
		# There are a few opportunities for attackers get get bad data passed
		# from decode over to encode to produce unexpected results (SACK
		# and timestamp manipulation seeming to be the most disasterous).
		# So don't make any life-critical decisions based on these options
		# remaining the same between the decode and encode functions.
		def self.encode(str)
			opts = str.split(/\s*,\s*/)
			binary_opts = ''
			opts.each do |opt|
				binary_opts << case opt
				when /^EOL$/i; "\x00"
				when /^NOP$/i; "\x01"
				when /^MSS\s*:/i; tcp_opts_short(2,opt)
				when /^WS\s*:/i; tcp_opts_char(3,opt)
				when /^SACK\.OK$/i; "\x04\x02"
				when /^SACK\s*:/i
					sack_opts = opt.split(/\s*:\s*/)[1].split(/\s*;\s*/).collect {|i| i.to_i}.pack("N*")
					[0x05,sack_opts.size+2,sack_opts].pack("CCa*")
				when /^ECHO\s*:/i; tcp_opts_long(6,opt)
				when /^ECHO.REPLY\s*:/i; tcp_opts_long(7,opt)
				when /^TS\s*:/i
					ts_opts = opt.split(/\s*:\s*/)[1].split(/\s*;\s*/).collect {|i| i.to_i}.pack("N*")
					[0x08,ts_opts.size+2,ts_opts].pack("CCa*")
				when /^POCP$/i; "\x09\x02"
				when /^POSP\s*:/i
					posp = [10,3,(opt.split(/\s*:\s*/)[1].to_i << 6)].pack("C3")
				when /^CC\s*:/i; tcp_opts_long(11,opt)
				when /^CC.NEW\s*:/i; tcp_opts_long(12,opt)
				when /^CC.ECHO\s*:/i; tcp_opts_long(13,opt)
				when /^ALT.CRC\s*:/i; tcp_opts_char(14,opt)
				when /^ALT.DATA\s*:/i; tcp_opts_variable(15,opt)
				when /^Skeeter\s*:/i; tcp_opts_variable(16,opt)
				when /^Bubba\s*:/i; tcp_opts_variable(17,opt)
				when /^TCO\s*:/i; tcp_opts_char(18,opt)
				when /^MD5\s*:/i; tcp_opts_variable(19,opt)
				when /^QSR\s*:/i; tcp_opts_variable(27,opt) # TODO: Do the bitwise math to match the decode. 
				when /^0x[0-9a-f][0-9a-f]\s*:/i; tcp_opts_variable(opt[0,4].to_i(16),opt)
				else
					raise ArgumentError, "Invalid tcp_options format or entry. Perhaps you want tcp_opts?"
				end
			end
			binary_opts
		end
		
		def self.tcp_opts_variable(optnum,optstr)
			ret = [optnum,0,optstr.split(/\s*:\s*/)[1]]
			ret[1] = ret.pack("CCH*").size
			ret.pack("CCH*")
		end

		def self.tcp_opts_char(optnum,optstr)
			[optnum,3,optstr.split(/\s*:\s*/)[1][0,3].to_i].pack("C3")
		end

		def self.tcp_opts_short(optnum,optstr)
			[optnum,4,optstr.split(/\s*:\s*/)[1].to_i].pack("CCn")
		end

		def self.tcp_opts_long(optnum,optstr)
			[optnum,6,optstr.split(/\s*:\s*/)[1].to_i].pack("CCN")
		end


		# XXX: Here be dragons!
		#
		# There are a few opportunities for attackers get get bad data passed
		# from decode over to encode to produce unexpected results (SACK
		# and timestamp manipulation seeming to be the most disasterous).
		# So don't make any life-critical decisions based on these options
		# remaining the same between the decode and encode functions.
		def self.decode(str)
			bare_opts = []
			invalid_opts = false
			invalid_opts = true if str.size > 44
			opts = StringIO.new(str)
			while opts.pos < opts.size
				bare_opts << case opts.read(1)
				when "\x00"; "\x00" 
				when "\x01"; "\x01"
				else
					arr = []
					opts.seek(opts.pos-1,0) # No StringIO.read(-1)? Lame.
					arr << opts.read(1)
					sz = opts.read(1)
					if sz.nil? # Every option needs a size.
						invalid_opts = true
					else
						sz = sz.unpack("C")[0]
						if sz <= 1 # Every option's size is 2 or greater.
							invalid_opts = true
						else
							arr << sz
							arr << opts.read(sz-2)
						end
					end
				end
			end
			if invalid_opts
				"INVALID:#{str}"
			else
				TcpOpts.translate(bare_opts)
			end
		end

		# Get an array of TCP options as produced by decode() and translate it into
		# something passing for human readable.
		def self.translate(arr)
			translated_opts = arr.collect do |opt|
				case opt
				when "\x00"; "EOL"
				when "\x01"; "NOP"
				else
					if opt[2].class == String
						TcpOpts.option_to_s(opt[0].unpack("C")[0],opt[2])
					else
						"INVALID:#{opt.pack("aC")}"
					end
				end
			end
			translated_opts.join(",")
		end

		# Option_to_s translates TCP option strings into a human-readable
		# form (really, a nerd-readable form, and only if that nerd has
		# a copy of the various RFC's handy). It makes big assumptions
		# that the sizes are RFC correct by this point, what with the 
		# unpacks and other presentations; for example, SACK-OK options
		# are always two bytes, and no payload, so if you get a SACK-OK
		# with a payload, it will be invisible when you process it with
		# option_to_s.
		#
		# Underruns and other argument errors /should/ be impossible. 
		# If you find one, please file a bug!
		#
		# If you require more precision than this (eg, to
		# account for malformed options), you should probably do
		# your own opts processing using the bare tcp_opts values.
		#
		# Eventually, option_to_s should get a lot smarter about
		# weirdly-formed options. And it at least shouldn't raise 
		# exceptions.
		def self.option_to_s(optnum,value)

			case optnum
			when 2; "MSS:#{value.unpack("n")}" # Max Segment Size
			when 3; "WS:#{value.unpack("C")}" # Window Scale
			when 4; "SACK.OK" # SACK Permitted
			when 5; sack_opt = "SACK:" # SACK values
				if value.size % 4 == 0 # Well formed or not.
					edges = value.scan(/[\x00-\xff]{4}/).collect {|h| h.unpack("N")}.join(';')
				else
					edges = value.unpack("H*")[0]
				end
				sack_opt + edges
			when 6; "ECHO:#{value.unpack("N")}" # Echo
			when 7; "ECHO.REPLY:#{value.unpack("N")}" # Echo Reply
			when 8; ts_opt = "TS:" # Timestamp and TS-echo reply
				ts_opt << value[0,4].unpack("N")[0].to_s
				ts_opt << ";"
				ts_opt << value[4,4].unpack("N")[0].to_s
			when 9; "POCP" # Partial Order Connection Permitted
			when 10; "POSP:" + # Partial Order Service Profile
				"%02d" % ((value.unpack("C")[0] >> 6).to_s(2)) # Partial Order bits
			when 11; "CC:#{value.unpack("N")}" # Connection Count. RFC 1644 is hi-larious, btw.
			when 12; "CC.NEW:#{value.unpack("N")}" # Connection Count New.
			when 13; "CC.EHCO:#{value.unpack("N")}" # Conn. Count Echo.
			when 14: "ALT.CRC:#{value.unpack("C")}" # Alt Checksum request
			when 15: "ALT.DATA:#{value.unpack("H*")}" # Alt checksum data. I'm too dumb for this.
			when 16: "Skeeter:#{value.unpack("H*")}" # Skeeter crypto.
			when 17: "Bubba:#{value.unpack("H*")}" # Bubba crypto.
			when 18: "TCO:#{value.unpack("C")}" # Trailer Checksum Option. Nobody knows what this is.
			when 19: "MD5:#{value.unpack("H*")}" # MD5 Signature Option. Hash-signed TCP? Outrageous!
			when 27: qsr_opt = "QSR:" # Quick-Start Request. Experimental in Jan 2007.
				qsr_val = []
				qsr_val << (value[0,1].unpack("C")[0] >> 4)
				qsr_val << (value[0,1].unpack("C")[0] & 0x0f)
				qsr_val << value[1,1].unpack("C")[0]
				qsr_val << value[2,4].unpack("N")[0] # Note bits 30,31 RFC-SHOULD be zero.
				qsr_opt + qsr_val.join(';')
				# Pretty much everything else is obsolete, experiemental, unused, or undoc'ed.
			else; "0x#{[optnum].pack("C").unpack("H*")[0].upcase}:#{value.unpack("H*")}"
			end
		end
	end
end