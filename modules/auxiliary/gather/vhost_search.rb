require 'msf/core'
require 'net/http'

class Metasploit3 < Msf::Auxiliary
	include Msf::Auxiliary::Report

	def initialize(info = {})
		super(update_info(info,
			'Name' => 'VirtualHost Search',
			'Description' => 'This module uses Bing and its dork "ip" to get virtual hosts from host. Based on search_email_collector\'s code',
			'Author' => [ 'Jose Selvi <jselvi{4t}pentester.es>' ],
			'License' => MSF_LICENSE,
			'Version' => '$Revision: 0 $'))

		register_options(
			[
				OptAddressRange.new('RHOSTS', [true, "The target address, range, or CIDR identifier"]),
				OptString.new('OUTFILE', [ false, "A filename to store the generated email list"]),

			], self.class)

		register_advanced_options(
			[
				OptString.new('PROXY', [ false, "Proxy server to route connection. <host>:<port>",nil]),
				OptString.new('PROXY_USER', [ false, "Proxy Server User",nil]),
				OptString.new('PROXY_PASS', [ false, "Proxy Server Password",nil]),
				OptInt.new('MAX_SEARCHES', [ true, "Maximum Bing Queries per IP",10])
			], self.class)
	end

	# Search IP at Bing.com
	def get_vhosts(ip)
		print_status("Searching VHosts in #{ip}")
		vhosts = []
		header = { 'User-Agent' => "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/525.13 (KHTML, like Gecko) Chrome/4.0.221.6 Safari/525.13"}
		clnt = Net::HTTP::Proxy(@proxysrv,@proxyport,@proxyuser,@proxypass).new("m.bing.com")
		searches = 0
		exceptions = ""
		while searches < @max_searches 
			# Query to Bing
			begin
				resp = clnt.get2("/search/search.aspx?A=webresults&Q=ip%3a#{ip}+#{exceptions}&D=Web&SCO=0",header)
				response = resp.body
			rescue
				print_error("Error in query. Please try later.")
				break
			end
			searches = searches + 1
			# Scan for links
			nlinks = 0
			response.scan(/REDIRURL=http%3a%2f%2f[a-zA-Z\.-]+/) do |t|
				if not t.match('bing.com')
					t.gsub!(/REDIRURL=http%3a%2f%2f/,"")
					t.gsub!(/\//,"")
					vhosts << t.downcase
					nlinks += 1
				end
			end
			if nlinks == 0
				break
			end
			vhosts = vhosts.uniq
			# Create -site exceptions for next query
			exceptions = ""
			vhosts.each do |vhost|
        			exceptions << "%20-site:#{vhost}"
			end
		end
		if searches == @max_searches
			print_error("Too much virtual hosts. Increase MAX_SEARCHES")
		end
		return vhosts.uniq
	end

	# Writing vhosts to file
	def write_output(data)
		print_status("Writing vhost list to #{datastore['OUTFILE']}...")
		::File.open(datastore['OUTFILE'], "ab") do |fd|
			fd.write(data)
		end
	end

	def run
		@max_searches = datastore['MAX_SEARCHES']
		if datastore['PROXY']
			@proxysrv,@proxyport = datastore['PROXY'].split(":")
			@proxyuser = datastore['PROXY_USER']
			@proxypass = datastore['PROXY_PASS']
		else
			@proxysrv,@proxyport = nil, nil
		end
		print_status("Harvesting vhosts .....")

		# Convert IPRange to IPs
		iplst = []
		iprange = datastore['RHOSTS']
		ipadd = Rex::Socket::RangeWalker.new(iprange)
		numip = ipadd.num_ips
		while (iplst.length < numip)
			ipa = ipadd.next_ip
			if (not ipa)
				break
			end
			iplst << ipa
		end

		# Check for each IP
		all_vhosts = []
		iplst.each do |target|
			vhosts = get_vhosts(target)
			print_status("Located #{vhosts.length} virtual hosts for #{target}")
			vhosts.each do |e|
				all_vhosts << e
				print_status("\t#{e.to_s}")
			end
		end

		# Write output file
		write_output(all_vhosts.uniq.join("\n")) if datastore['OUTFILE']
	end
end
