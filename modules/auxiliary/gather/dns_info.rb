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
			'Name'		   => 'DNS Base Information',
			'Description'	=> %q{
					The module enumerates basic DNS information for a given domain. Information
					enumerated is A, AAAA, NS and MX records for the given domain.
			},
			'Author'		=> [ 'Carlos Perez <carlos_perez[at]darkoperator.com>' ],
			'License'		=> BSD_LICENSE
			))

		register_options(
			[
				OptString.new('DOMAIN', [ true, "The target domain name"]),
				OptAddress.new('NS', [ false, "Specify the name server to use for queries, otherwise use the system configured DNS Server is used." ]),

			], self.class)

		register_advanced_options(
			[
				OptInt.new('RETRY', [ false, "Number of tries to resolve a record if no response is received.", 2]),
				OptInt.new('RETRY_INTERVAL', [ false, "Number of seconds to wait before doing a retry.", 2]),
			], self.class)
	end

	def run
		print_status("Enumerating #{datastore['DOMAIN']}")
		@res = Net::DNS::Resolver.new()

		if datastore['RETRY']
			@res.retry = datastore['RETRY'].to_i
		end

		if datastore['RETRY_INTERVAL']
			@res.retry_interval = datastore['RETRY_INTERVAL'].to_i
		end

		wildcard(datastore['DOMAIN'])
		switchdns() if not datastore['NS'].nil?

		get_ip(datastore['DOMAIN']).each do |r|
			print_good("#{r[:host]} #{r[:address]} #{r[:type]}")
			report_host(:host => r[:address])
		end

		get_ns(datastore['DOMAIN']).each do |r|
			print_good("#{r[:host]} #{r[:address]} #{r[:type]}")
			report_host(:host => r[:address], :name => r[:host])
			report_service(
				:host => r[:address],
				:name => "dns",
				:port => 53,
				:proto => "udp"
			)
		end

		get_soa(datastore['DOMAIN']).each do |r|
			print_good("#{r[:host]} #{r[:address]} #{r[:type]}")
			report_host(:host => r[:address], :name => r[:host])
		end

		get_mx(datastore['DOMAIN']).each do |r|
			print_good("#{r[:host]} #{r[:address]} #{r[:type]}")
			report_host(:host => r[:address], :name => r[:host])
			report_service(
				:host => r[:address],
				:name => "smtp",
				:port => 25,
				:proto => "tcp"
			)
		end

		get_txt(datastore['DOMAIN']).each do |r|
			report_note(:host => datastore['DOMAIN'],
							:proto => 'UDP',
							:port => 53,
							:type => 'dns.info',
							:data => {:text => r[:text]})
		end
	end

	#---------------------------------------------------------------------------------
	def wildcard(target)
		rendsub = rand(10000).to_s
		query = @res.query("#{rendsub}.#{target}", "A")
		if query.answer.length != 0
			print_status("This Domain has Wild-cards Enabled!!")
			query.answer.each do |rr|
				print_status("Wild-card IP for #{rendsub}.#{target} is: #{rr.address.to_s}") if rr.class != Net::DNS::RR::CNAME
				report_note(:host => datastore['DOMAIN'],
							:proto => 'UDP',
							:port => 53,
							:type => 'dns.wildcard',
							:data => "Wildcard IP for #{rendsub}.#{target} is: #{rr.address.to_s}")
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
				record = {}
				record[:host] = host
				record[:type] = "A"
				record[:address] = rr.address.to_s
				results << record
			end
		end
		query1 = @res.search(host, "AAAA")
		if (query1)
			query1.answer.each do |rr|
				record = {}
				record[:host] = host
				record[:type] = "AAAA"
				record[:address] = rr.address.to_s
				results << record
			end
		end
		return results
	end

	#---------------------------------------------------------------------------------
	def get_ns(target)
		results = []
		query = @res.query(target, "NS")
		if (query)
			(query.answer.select { |i| i.class == Net::DNS::RR::NS}).each do |rr|
				get_ip(rr.nsdname).each do |r|
					record = {}
					record[:host] = rr.nsdname.gsub(/\.$/,'')
					record[:type] = "NS"
					record[:address] = r[:address].to_s
					results << record
				end
			end
		end
		return results
	end

	#---------------------------------------------------------------------------------
	def get_soa(target)
		results = []
		query = @res.query(target, "SOA")
		if (query)
			(query.answer.select { |i| i.class == Net::DNS::RR::SOA}).each do |rr|
				if Rex::Socket.dotted_ip?(rr.mname)
					record = {}
					record[:host] = rr.mname
					record[:type] = "SOA"
					record[:address] = rr.mname
					results << record
				else
					get_ip(rr.mname).each do |ip|
						record = {}
						record[:host] = rr.mname.gsub(/\.$/,'')
						record[:type] = "SOA"
						record[:address] = ip[:address].to_s
						results << record
					end
				end
			end
		end
		return results
	end

	#---------------------------------------------------------------------------------
	def get_txt(target)
		results = []
		query = @res.query(target, "TXT")
		if (query)
			query.answer.each do |rr|
				record = {}
				print_good("Text: #{rr.txt}, TXT")
				record[:host] = target
				record[:text] = rr.txt
				record[:type] = "TXT"
				results << record
			end
		end
		return results
	end

	#---------------------------------------------------------------------------------
	def get_mx(target)
		results = []
		query = @res.query(target, "MX")
		if (query)
			(query.answer.select { |i| i.class == Net::DNS::RR::MX}).each do |rr|
				if Rex::Socket.dotted_ip?(rr.exchange)
					record = {}
					record[:host] = rr.exchange
					record[:type] = "MX"
					record[:address] = rr.exchange
					results << record
				else
					get_ip(rr.exchange).each do |ip|
						record = {}
						record[:host] = rr.exchange.gsub(/\.$/,'')
						record[:type] = "MX"
						record[:address] = ip[:address].to_s
						results << record
					end
				end
			end
		end
		return results
	end

	#---------------------------------------------------------------------------------
	def switchdns()
		print_status("Using DNS server: #{datastore['NS']}")
		@res.nameserver=(datastore['NS'])
		@nsinuse = datastore['NS']
	end
end

