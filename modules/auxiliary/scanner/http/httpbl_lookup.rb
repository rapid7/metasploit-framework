##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require "net/dns/resolver"

class Metasploit3 < Msf::Auxiliary
	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::Report

	def initialize(info = {})
		super(update_info(info,
			'Name'		   => 'Http:BL Lookup',
			'Description'	=> %q{
					This module can be used to enumerate information
				about an IP addresses from Project HoneyPot's HTTP Block List.
			},
			'Author' 		=> [ 'mubix' ],
			'License'		=> MSF_LICENSE,
			'References' 	=>
				[
					['URL', 'http://www.projecthoneypot.org/httpbl_api.php'],
				]
			))


		register_options(
			[
				# OptAddressRange.new('RHOSTS', [false, "The target address, range, or CIDR identifier"]),
				OptString.new('HTTPBL_APIKEY', [ true, "Your HTTP:BL api key"])
			], self.class)
	end

	# Not compatible today
	def support_ipv6?
		false
	end

	def resolve(ip)
		results = ''
		apikey = datastore['HTTPBL_APIKEY']
		query = apikey + '.' + ip.split('.').reverse.join('.') + '.dnsbl.httpbl.org'
		begin
			results = Resolv::DNS.new.getaddress(query).to_s
		rescue Resolv::ResolvError => e
			results = 0
		rescue => e
			print_error e
			results = 0
		end
		return results
	end

	def translate(ip)
		ip.split('.')
	end

	def run_host(ip)
		result = resolve(ip)
		if result != 0
			breakup = result.split('.')
			lastseen = breakup[1]
			threatnum = breakup[2].to_i
			if threatnum < 25 then
				threat = "less than 100"
			elsif threatnum > 25 and threatnum < 49 then
				threat = "over 100"
			elsif threatnum > 50 and threatnum < 99 then
				threat = "over 10,000"
			elsif threatnum > 75 then
				threat = "over 1 million"
			end

			typenum = breakup[3]
			typestring = case typenum
				when '0' then 'Search Engine'
				when '1' then 'Suspicious'
				when '2' then 'Harvester'
				when '3' then 'Suspicious & Harvester'
				when '4' then 'Comment Spammer'
				when '5' then 'Suspicious & Comment Spammer'
				when '6' then 'Harvester & Comment Spammer'
				when '7' then 'Suspicious & Harvester & Comment Spammer'
				else
					"Unknown"
			end

			print_status ""
			print_status "#{ip} resloves to #{result} which means: #{typestring}"
			print_status "=> it was last seen #{lastseen} day ago and has a threat score of #{threatnum} or \'#{threat} spam messages\'"
			print_status "=> more info here: http://www.projecthoneypot.org/ip_#{ip}\n"
		end
	end
end
