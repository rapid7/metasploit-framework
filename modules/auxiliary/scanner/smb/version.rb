##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to 
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/projects/Framework/
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary

	
	# Exploit mixins should be called first
	include Msf::Exploit::Remote::DCERPC
	include Msf::Exploit::Remote::SMB
	
	# Scanner mixin should be near last
	include Msf::Auxiliary::Scanner

	# Aliases for common classes
	SIMPLE = Rex::Proto::SMB::SimpleClient
	XCEPT  = Rex::Proto::SMB::Exceptions
	CONST  = Rex::Proto::SMB::Constants

	
	def initialize
		super(
			'Name'        => 'SMB Version Detection',
			'Version'     => '$Revision$',
			'Description' => 'Display version information about each system',
			'Author'      => 'hdm',
			'License'     => MSF_LICENSE
		)
		
		deregister_options('RPORT')
	end

	# Overload the RPORT setting
	def rport
		@target_port
	end


	def dword_align(offset)
		(offset / 4.0).to_i * 4
	end
	
	def read_unicode(buff,offset)
		return nil if offset > (buff.length-1)
		
		p buff[offset,32]
		
		eoff = buff[offset,buff.length].index("\x00\x00")
		buff[offset, eoff]
	end

	def smb_enumprinters(flags, name, level, blen)
		stub =
			NDR.long(flags) +
			(name ? NDR.uwstring(name) : NDR.long(0)) +
			NDR.long(level) +
			NDR.long(rand(0xffffffff)+1)+
			NDR.long(blen) +
			"\x00" * blen +
			NDR.long(blen)
		handle = dcerpc_handle(
			'12345678-1234-abcd-ef00-0123456789ab', '1.0', 
			'ncacn_np', ["\\SPOOLSS"]
		)

		dcerpc_bind(handle)

		begin
			dcerpc.call(0x00, stub)
			return dcerpc.last_response.stub_data
		rescue => e
			return nil
		end				
	end
	
	
	def smb_enumprintproviders
		resp = smb_enumprinters(8, nil, 1, 0)
		return nil if not resp		
		rptr, tmp, blen = resp.unpack("V*")

		resp = smb_enumprinters(8, nil, 1, blen)
		return nil if not resp
		
		bcnt,pcnt,stat = resp[-12, 12].unpack("VVV")
		return nil if stat != 0
		return nil if pcnt == 0
		return nil if bcnt > blen
		return nil if pcnt < 3

		return resp

		#
		# The correct way, which leads to invalid offsets :-(
		#
		providers = []
		
		0.upto(pcnt-1) do |i|
			flags,desc_o,name_o,comm_o = resp[8 + (i*16), 16].unpack("VVVV")

			desc = read_unicode(resp,8+desc_o).gsub("\x00", '')
			name = read_unicode(resp,8+name_o).gsub("\x00", '')
			comm = read_unicode(resp,8+comm_o).gsub("\x00", '')
			providers << [flags,desc,name,comm]
		end

		providers
	end

	
	# Fingerprint a single host
	def run_host(ip)

		[[139, false], [445, true]].each do |info|

		@target_port = info[0]
		self.smb_direct = info[1]
		
		begin
			connect()
			smb_login()
				
			os = 'Unknown'
			sp = ''

			case smb_peer_os()
				when 'Windows NT 4.0'
					os = 'Windows NT 4.0'
					
				when 'Windows 5.0'
					os = 'Windows 2000'
					
				when 'Windows 5.1'
					os = 'Windows XP'
					
				when /Windows XP (\d+) Service Pack (\d+)/
					os = 'Windows XP'
					sp = 'Service Pack ' + $2
					
				when /Windows Server 2003 (\d+)$/
					os = 'Windows 2003'
					sp = 'No Service Pack'
					
				when /Windows Server 2003 (\d+) Service Pack (\d+)/
					os = 'Windows 2003'
					sp = 'Service Pack ' + $2
					
				when /Windows Server 2003 R2 (\d+) Service Pack (\d+)/
					os = 'Windows 2003 R2'
					sp = 'Service Pack ' + $2
					
				when /Windows Vista \(TM\) (\w+|\w+ \w+) (\d+) Service Pack (\d+)/
					os = 'Windows Vista ' + $1
					sp = 'Service Pack ' + $3
					
				when /Windows Vista \(TM\) (\w+|\w+ \w+) (\d+)/
					os = 'Windows Vista ' + $1
					sp = '(Build ' + $2 + ')'
					
				when /Windows Server \(R\) 2008 (\w+|\w+ \w+) (\d+) Service Pack (\d+)/	
					os = 'Windows 2008 ' + $1
					sp = 'Service Pack ' + $3			

				when /Windows Server \(R\) 2008 (\w+|\w+ \w+) (\d+)/	
					os = 'Windows 2008 ' + $1
					sp = '(Build ' + $2 + ')'
																
				when 'Unix'
					os = 'Unix'
					sv = smb_peer_lm()
					case sv
						when /Samba\s+(.*)/i
							sp = 'Samba ' + $1
					end
			end


			if (os == 'Windows XP' and sp.length == 0)
				# SRVSVC was blocked in SP2
				begin
					smb_create("\\SRVSVC")
					sp = 'Service Pack 0 / 1'
				rescue ::Rex::Proto::SMB::Exceptions::ErrorCode => e
					if (e.error_code == 0xc0000022)
						sp = 'Service Pack 2+'
					end
				end
			end
			
			if (os == 'Windows 2000' and sp.length == 0)
				# LLSRPC was blocked in a post-SP4 update
				begin
					smb_create("\\LLSRPC")
					sp = 'Service Pack 0 - 4'
				rescue ::Rex::Proto::SMB::Exceptions::ErrorCode => e
					if (e.error_code == 0xc0000022)
						sp = 'Service Pack 4 with MS05-010+'
					end
				end
			end

			#
			# Perform granular XP SP checks if LSARPC is exposed
			#
			if (os == 'Windows XP')

				#
				# Service Pack 2 added a range(0,64000) to opnum 0x22 in SRVSVC
				#
				begin
				
					handle = dcerpc_handle(
						'4b324fc8-1670-01d3-1278-5a47bf6ee188', '3.0', 
						'ncacn_np', ["\\BROWSER"]
					)
	
					dcerpc_bind(handle)
					
					begin
						stub = 
							NDR.uwstring(Rex::Text.rand_text_alpha(rand(10)+1)) +
							NDR.wstring(Rex::Text.rand_text_alpha(rand(10)+1))  +
							NDR.long(64001) +
							NDR.long(0) +
							NDR.long(0)
						
						dcerpc.call(0x22, stub)
						sp = "Service Pack 0 / 1"
					rescue ::Rex::Proto::SMB::Exceptions::ErrorCode
					rescue ::Rex::Proto::DCERPC::Exceptions::Fault => e
						sp = "Service Pack 2+"
					end

				rescue ::Interrupt
					raise $!
				rescue ::Rex::Proto::SMB::Exceptions::ErrorCode
				rescue ::Rex::Proto::SMB::Exceptions::ReadPacket
				rescue ::Exception
				end


				#
				# Service Pack 3 added opnum 0x4F in LSARPC
				# This PIPE is only available when file sharing is on
				#
				begin
					handle = dcerpc_handle(
						'12345778-1234-abcd-ef00-0123456789ab', '0.0', 
						'ncacn_np', ["\\LSARPC"]
					)
								
					dcerpc_bind(handle)
					
					if(sp == "Service Pack 2+")
						sp = "Service Pack 2"
					end
													
					begin
						stub = 
							NDR.long(0) + 
							NDR.long(0)
							
						dcerpc.call(0x4f, stub)
						sp = "Service Pack 3"
					rescue ::Rex::Proto::SMB::Exceptions::ErrorCode => e
						if(e.error_code == 0xc0000022)
							sp = "Service Pack 3"
						end						
					rescue ::Rex::Proto::DCERPC::Exceptions::Fault
						# SP2 or below
					end
		
				rescue ::Interrupt
					raise $!
				rescue ::Rex::Proto::SMB::Exceptions::ErrorCode
				rescue ::Rex::Proto::SMB::Exceptions::LoginError
				rescue ::Exception => e
					print_status("Error SP2/SP3 check: #{e.class} #{e}")
				end
				

				#
				# DHCP Client Service and Wireless both had SP3 changes, but
				# calling any opnums results in the disconnected pipe SMB error.
				# Still looking for a better XP SP2 vs XP SP3 method over SMB
				#			
				
			end


			#
			# Remote language detection via Print Providers
			# Credit: http://immunityinc.com/downloads/Remote_Language_Detection_in_Immunity_CANVAS.odt
			#

			lang = 'Unknown'
	
			sigs = 
			{
				'English' =>
					[
						Rex::Text.to_unicode('Windows NT Remote Printers'),
						Rex::Text.to_unicode('LanMan Print Services')
					],
				'Spanish' =>
					[
						Rex::Text.to_unicode('Impresoras remotas Windows NT'),
						Rex::Text.to_unicode('Impresoras remotas de Windows NT')
					],
				'Italian' =>
					[
						Rex::Text.to_unicode('Stampanti remote di Windows NT'),
						Rex::Text.to_unicode('Servizi di stampa LanMan')
					],
				'French' =>
					[
						Rex::Text.to_unicode('Imprimantes distantes NT'),
						Rex::Text.to_unicode('Imprimantes distantes pour Windows NT'),
						Rex::Text.to_unicode("Services d'impression LanMan")
					],
				'German' =>
					[
						Rex::Text.to_unicode('Remotedrucker')
					],
				'Portugese - Brazilian' =>
					[
						Rex::Text.to_unicode('Impr. remotas Windows NT'),
						Rex::Text.to_unicode('Impressoras remotas do Windows NT')
					],
				'Portguese' =>
					[
						Rex::Text.to_unicode('Imp. remotas do Windows NT')
					],
				'Hungarian' =>
					[
						Rex::Text.to_unicode('Távoli nyomtatók')
					],
				'Finnish' =>
					[
						Rex::Text.to_unicode('Etätulostimet')
					],
				'Dutch' =>
					[
						Rex::Text.to_unicode('Externe printers voor NT')
					],
				'Swedish' =>
					[
						Rex::Text.to_unicode('Fjärrskrivare')
					],
				'Polish' =>
					[
						Rex::Text.to_unicode('Zdalne drukarki')
					],
				'Turkish' =>
					[
						"\x59\x00\x61\x00\x7a\x00\x31\x01\x63\x00\x31\x01\x6c\x00\x61\x00\x72\x00"
					],
				'Japanese' =>
					[
						"\xea\x30\xe2\x30\xfc\x30\xc8\x30\x20\x00\xd7\x30\xea\x30\xf3\x30\xbf\x30"
					],
				'Chinese - Traditional' =>
					[
						"\xdc\x8f\x0b\x7a\x53\x62\x70\x53\x3a\x67"
					],
				'Chinese - Traditional / Taiwan' => 
					[
						"\x60\x90\xef\x7a\x70\x53\x68\x88\x5f\x6a",
					],
				'Korean' =>
					[
						"\xd0\xc6\xa9\xac\x20\x00\x04\xd5\xb0\xb9\x30\xd1",
					],
				'Russian' =>
					[
						"\x1f\x04\x40\x04\x38\x04\x3d\x04\x42\x04\x35\x04\x40\x04\x4b\x04\x20\x00\x43\x04\x34\x04\x30\x04\x3b\x04\x35\x04\x3d\x04\x3d\x04\x3e\x04\x33\x04\x3e\x04\x20\x00\x34\x04\x3e\x04\x41\x04\x42\x04\x43\x04\x3f\x04\x30\x04",
					],
					
			}
			
			begin
				prov = smb_enumprintproviders()
				if(prov)
					sigs.each_key do |k|
						sigs[k].each do |s|
							if(prov.index(s))
								lang = k
								break
							end
							break if lang != 'Unknown'
						end
						break if lang != 'Unknown'
					end

					if(lang == 'Unknown')
					
						@fpcache ||= {}
						mhash = ::Digest::MD5.hexdigest(prov[4,prov.length-4])
						
						if(not @fpcache[mhash])
						
							buff = "\n"
							buff << "*** NEW FINGERPRINT: PLEASE SEND TO [ msfdev[at]metasploit.com ]\n"
							buff << " VERS: #{self.version}\n"
							buff << " HOST: #{rhost}\n"
							buff << "   OS: #{os}\n"
							buff << "   SP: #{sp}\n"

							prov.unpack("H*")[0].scan(/.{64}|.*/).each do |line|
								next if line.length == 0
								buff << "   FP: #{line}\n"
							end

							prov.split(/\x00\x00+/).each do |line|
								line.gsub!("\x00",'')
								line.strip!
								next if line.length < 6

								buff <<  "  TXT: #{line}\n"
							end

							buff << "*** END FINGERPRINT\n"

							print_line(buff)
							
							@fpcache[mhash] = true
						end
						
					end
				end
			rescue ::Interrupt
				raise $!
			rescue ::Rex::Proto::SMB::Exceptions::ErrorCode
			end
	
 			print_status("#{ip} is running #{os} #{sp} (language: #{lang})")
			
			if (os == 'Unknown') 
				print_status("#{ip} NativeOS: #{smb_peer_os()}")
				print_status("#{ip} NativeLM: #{smb_peer_lm()}")
			end
			
			disconnect
			
			return
		rescue ::Rex::Proto::SMB::Exceptions::ErrorCode
		rescue ::Rex::Proto::SMB::Exceptions::LoginError => e
			
			# Vista has 139 open but doesnt like *SMBSERVER
			if(e.to_s =~ /server refused our NetBIOS/)
				next
			end
			
			return
		rescue ::Rex::ConnectionRefused, ::Rex::ConnectionTimeout
			next
		rescue ::Errno::ECONNRESET, ::Rex::HostUnreachable
		rescue ::Exception => e
			print_error("#{ip}: #{e.class} #{e} #{e.backtrace}")
		ensure
			disconnect
		end
		end
	end

end
