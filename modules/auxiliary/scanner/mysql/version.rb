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
	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::Report

	def initialize
		super(
			'Name'        => 'MySQL Server Version Enumeration',
			'Description' => %q{
				Enumerates the version of MySQL servers
			},
			'Version'     => '$Revision$',
			'Author'      => 'kris katterjohn',
			'License'     => MSF_LICENSE
		)

		register_options([
			Opt::RPORT(3306)
		])
	end

	# Based on my mysql-info NSE script
	def run_host(ip)
		begin
			s = connect(false)
			data = s.get
			disconnect(s)
		rescue ::Exception
			print_error("Error: #{$!}")
			return
		end

		offset = 0

		l0, l1, l2 = data[offset, 3].unpack('CCC')
		length = l0 | (l1 << 8) | (l2 << 16)

		# Read a bad amount of data
		return if length != (data.length - 4)

		offset += 4

		proto = data[offset, 1].unpack('C')

		# Error condition
		return if proto == 255

		offset += 1

		version = data[offset..-1].unpack('Z*')

		print_status("#{rhost}:#{rport} is running MySQL #{version} (protocol #{proto})")
	end
end

