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
			'Name'		   => 'DNS Host and Subdomain Brutefoce Module',
			'Description'	=> %q{
					This module uses a dictionary to perform a bruteforce on Hostnames and Subdomains
					available under a given domain.
			},
			'Author'		=> [ 'Carlos Perez <carlos_perez[at]darkoperator.com>' ],
			'License'		=> BSD_LICENSE
			))

		register_options(
			[
				OptString.new('DOMAIN', [ true, "The target domain name"]),
				OptAddress.new('NS', [ false, "Specify the nameserver to use for queries, otherwise use the system DNS" ]),
				OptPath.new('WORDLIST', [ false, "Wordlist file for domain name brute force.",
							File.join(Msf::Config.install_root, "data", "wordlists", "namelist.txt")]),

			], self.class)

		register_advanced_options(
			[
				OptInt.new('RETRY', [ false, "Number of times to try to resolve a record if no response is received", 2]),
				OptInt.new('RETRY_INTERVAL', [ false, "Number of seconds to wait before doing a retry", 2]),
				OptInt.new('THREADS', [ false, "Number of threads", 1]),
			], self.class)
	end

	def run
		print_status("Enumerating #{datastore['DOMAIN']}")
		@res = Net::DNS::Resolver.new()
		@res.retry = datastore['RETRY'].to_i
		@res.retry_interval = datastore['RETRY_INTERVAL'].to_i
		wildcard(datastore['DOMAIN'])
		switchdns() if not datastore['NS'].nil?
		dnsbrt(datastore['DOMAIN'])
	end

	#---------------------------------------------------------------------------------
	def wildcard(target)
		rendsub = rand(10000).to_s
		query = @res.query("#{rendsub}.#{target}", "A")
		if query.answer.length != 0
			print_status("This Domain has Wildcards Enabled!!")
			query.answer.each do |rr|
				print_warning("Wildcard IP for #{rendsub}.#{target} is: #{rr.address.to_s}") if rr.class != Net::DNS::RR::CNAME
			end
			return true
		else
			return false
		end
	end

	#---------------------------------------------------------------------------------
	def get_ip(host)
		results = []
		query = @res.search(host, "A")
		if (query)
			query.answer.each do |rr|
				if rr.type == "CNAME"
					results = results + get_ip(rr.cname)
				else
					record = {}
					record[:host] = host
					record[:type] = "AAAA"
					record[:address] = rr.address.to_s
					results << record
				end
			end
		end
		query1 = @res.search(host, "AAAA")
		if (query1)
			query1.answer.each do |rr|
				if rr.type == "CNAME"
					results = results + get_ip(rr.cname)
				else
					record = {}
					record[:host] = host
					record[:type] = "AAAA"
					record[:address] = rr.address.to_s
					results << record
				end
			end
		end
		return results
	end

	#---------------------------------------------------------------------------------
	def switchdns()
		print_status("Using DNS Server: #{datastore['NS']}")
		@res.nameserver=(datastore['NS'])
		@nsinuse = datastore['NS']
	end

	def dnsbrt(domain)
		print_status("Performing bruteforce against #{domain}")
		queue = []
		File.open(datastore['WORDLIST'], 'rb').each_line do |testd|
			queue << testd.strip
		end
		while(not queue.empty?)
			tl = []
			1.upto(datastore['THREADS']) do
				tl << framework.threads.spawn("Module(#{self.refname})-#{domain}", false, queue.shift) do |testf|
					Thread.current.kill if not testf
					vprint_status("Testing #{testf}.#{domain}")
					get_ip("#{testf}.#{domain}").each do |i|
						print_good("#{i[:host]} #{i[:address]}")
						report_host(
							:host => i[:address].to_s,
							:name => i[:host].gsub(/\.$/,'')
						)
					end
				end
			end
			if(tl.length == 0)
				break
			end
			tl.first.join
			tl.delete_if { |t| not t.alive? }
		end
	end
end

