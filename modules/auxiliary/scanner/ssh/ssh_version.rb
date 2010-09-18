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

	include Msf::Exploit::Remote::Tcp
	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::Report

	def initialize
		super(
			'Name'        => 'SSH Version Scannner',
			'Version'     => '$Revision$',
			'Description' => 'Detect SSH Version.',
			'References'  =>
				[
					[ 'URL', 'http://en.wikipedia.org/wiki/SecureShell' ],
				],
			'Author'      => [ 'Daniel van Eeden <metasploit[at]myname.nl>' ],
			'License'     => MSF_LICENSE
		)

		register_options(
		[
			Opt::RPORT(22),
			OptInt.new('TIMEOUT', [true, 'Timeout for the SSH probe', 30])
		], self.class)
	end

	def to
		return 30 if datastore['TIMEOUT'].to_i.zero?
		datastore['TIMEOUT'].to_i
	end

	def run_host(target_host)
		begin
			timeout(to) do

				connect

				ver = sock.get_once(-1, 5)

				if (ver and ver =~ /SSH/)
					ver,msg = (ver.split(/(\n|\r)/))
					print_status("#{target_host}:#{rport}, SSH server version: #{ver}")
					report_service(:host => rhost, :port => rport, :name => "ssh", :info => ver)
				else
					print_error("#{target_host}:#{rport}, SSH server version detection failed!")
				end

				disconnect
			end

		rescue Timeout::Error
			print_error("#{target_host}:#{rport}, Server timed out after #{to} seconds. Skipping.")
		end
	end
end

