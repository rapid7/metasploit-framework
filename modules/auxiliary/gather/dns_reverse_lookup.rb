##
# ## This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require "net/dns/resolver"
require 'rex'

class Metasploit3 < Msf::Auxiliary
	include Msf::Auxiliary::Report

	def initialize(info = {})
		super(update_info(info,
			'Name'		   => 'DNS Reverse Lookup',
			'Description'	=> %q{
					This module performs a Reverse Lookup against a given IP Range.
			},
			'Author'		=> [ 'Carlos Perez <carlos_perez[at]darkoperator.com>' ],
			'License'		=> BSD_LICENSE
			))

		register_options(
			[
				OptAddressRange.new('RANGE', [true, 'IP Range to perform reverse lookup against.', nil]),
				OptAddress.new('NS', [ false, "Specify the nameserver to use for queries, otherwise use the system DNS" ]),

			], self.class)

		register_advanced_options(
			[
				OptInt.new('RETRY', [ false, "Number of times to try to resolve a record if no response is received", 2]),
				OptInt.new('RETRY_INTERVAL', [ false, "Number of seconds to wait before doing a retry", 2]),
				OptInt.new('THREADS', [ true, "Number of seconds to wait before doing a retry", 2]),
			], self.class)
	end

	def run
		@res = Net::DNS::Resolver.new()

		if datastore['RETRY']
			@res.retry = datastore['RETRY'].to_i
		end

		if datastore['RETRY_INTERVAL']
			@res.retry_interval = datastore['RETRY_INTERVAL'].to_i
		end

		@threadnum = datastore['THREADS'].to_i
		switchdns() if not datastore['NS'].nil?
		reverselkp(datastore['RANGE'])
	end

	#-------------------------------------------------------------------------------
	def reverselkp(iprange)
		print_status("Running Reverse Lookup against ip range #{iprange}")
		ar = Rex::Socket::RangeWalker.new(iprange)
		tl = []
		while (true)
			# Spawn threads for each host
			while (tl.length <= @threadnum)
				ip = ar.next_ip
				break if not ip
				tl << framework.threads.spawn("Module(#{self.refname})-#{ip}", false, ip.dup) do |tip|
					begin
						query = @res.query(tip)
						query.each_ptr do |addresstp|
							print_status("Host Name: #{addresstp} IP Address: #{tip.to_s}")

							report_host(
							:host => tip.to_s,
							:name => addresstp
							)
						end
					rescue ::Interrupt
						raise $!
					rescue ::Rex::ConnectionError
					rescue ::Exception => e
						print_error("Error: #{tip}: #{e.message}")
					end
				end
			end
			# Exit once we run out of hosts
			if(tl.length == 0)
				break
			end
			tl.first.join
			tl.delete_if { |t| not t.alive? }
		end
	end

	#---------------------------------------------------------------------------------
	def switchdns()
		print_status("Using DNS Server: #{datastore['NS']}")
		@res.nameserver=(datastore['NS'])
		@nsinuse = datastore['NS']
	end
end

