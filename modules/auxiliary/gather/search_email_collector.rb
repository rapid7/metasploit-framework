##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'net/http'

class Metasploit3 < Msf::Auxiliary
	include Msf::Auxiliary::Report

	def initialize(info = {})
		super(update_info(info,
			'Name' => 'Search Engine Domain Email Address Collector',
			'Description' => %q{
					This module uses Google, Bing and Yahoo to create a list of
				valid email addresses for the target domain.
			},
			'Author' => [ 'Carlos Perez <carlos_perez[at]darkoperator.com>' ],
			'License' => MSF_LICENSE))

		register_options(
			[
				OptString.new('DOMAIN', [ true, "The domain name to locate email addresses for"]),
				OptBool.new('SEARCH_GOOGLE', [ true, 'Enable Google as a backend search engine', true]),
				OptBool.new('SEARCH_BING', [ true, 'Enable Bing as a backend search engine', true]),
				OptBool.new('SEARCH_YAHOO', [ true, 'Enable Yahoo! as a backend search engine', true]),
				OptString.new('OUTFILE', [ false, "A filename to store the generated email list"]),

			], self.class)

		register_advanced_options(
			[
				OptString.new('PROXY', [ false, "Proxy server to route connection. <host>:<port>",nil]),
				OptString.new('PROXY_USER', [ false, "Proxy Server User",nil]),
				OptString.new('PROXY_PASS', [ false, "Proxy Server Password",nil])
			], self.class)

	end

	#Search google.com for email's of target domain
	def search_google(targetdom)
		print_status("Searching Google for email addresses from #{targetdom}")
		response = ""
		emails = []
		header = { 'User-Agent' => "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"}
		clnt = Net::HTTP::Proxy(@proxysrv,@proxyport,@proxyuser,@proxypass).new("www.google.com")
		searches = ["100", "200","300", "400", "500"]
		searches.each { |num|
			resp = clnt.get2("/search?hl=en&lr=&ie=UTF-8&q=%40"+targetdom+"&start=#{num}&sa=N&filter=0&num=100",header)
			response << resp.body
		}
		print_status("Extracting emails from Google search results...")
		response.gsub!(/<.?em?[>]*>/, "")
		response.scan(/[A-Z0-9._%+-]+@#{targetdom}/i) do |t|
			emails << t
		end
		return emails.uniq
	end

	#Search Yahoo.com for email's of target domain
	def search_yahoo(targetdom)
		print_status("Searching Yahoo for email addresses from #{targetdom}")
		response = ""
		emails = []
		header = { 'User-Agent' => "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/525.13 (KHTML, like Gecko) Chrome/4.0.221.6 Safari/525.13"}
		clnt = Net::HTTP::Proxy(@proxysrv,@proxyport,@proxyuser,@proxypass).new("search.yahoo.com")
		searches = ["1", "101","201", "301", "401", "501"]
		searches.each { |num|
			resp = clnt.get2("/search?p=%40#{targetdom}&n=100&ei=UTF-8&va_vt=any&vo_vt=any&ve_vt=any&vp_vt=any&vd=all&vst=0&vf=all&vm=p&fl=0&fr=yfp-t-152&xargs=0&pstart=1&b=#{num}",header)
			response << resp.body

		}
		print_status("Extracting emails from Yahoo search results...")
		response.gsub!(/<.?b?[>]*>/, "")
		response.scan(/[A-Z0-9._%+-]+@#{targetdom}/i) do |t|
			emails << t.downcase
		end
		return emails.uniq
	end

	#Search Bing.com for email's of target domain
	def search_bing(targetdom)
		print_status("Searching Bing email addresses from #{targetdom}")
		response = ""
		emails = []
		header = { 'User-Agent' => "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/525.13 (KHTML, like Gecko) Chrome/4.0.221.6 Safari/525.13"}
		clnt = Net::HTTP::Proxy(@proxysrv,@proxyport,@proxyuser,@proxypass).new("www.bing.com")
		searches = 1
		while searches < 201
			begin
				resp = clnt.get2("/search?q=%40#{targetdom}&first=#{searches.to_s}",header)
				response << resp.body
			rescue
			end
			searches = searches + 10
		end
		print_status("Extracting emails from Bing search results...")
		response.gsub!(/<.?strong?[>]*>/, "")
		response.scan(/[A-Z0-9._%+-]+@#{targetdom}/i) do |t|
			emails << t.downcase
		end
		return emails.uniq
	end

	#for writing file with all email's found
	def write_output(data)
		print_status("Writing email address list to #{datastore['OUTFILE']}...")
		::File.open(datastore['OUTFILE'], "ab") do |fd|
			fd.write(data)
		end
	end

	def run
		if datastore['PROXY']
			@proxysrv,@proxyport = datastore['PROXY'].split(":")
			@proxyuser = datastore['PROXY_USER']
			@proxypass = datastore['PROXY_PASS']
		else
			@proxysrv,@proxyport = nil, nil
		end
		print_status("Harvesting emails .....")


		target = datastore['DOMAIN']

		emails = []
		emails << search_google(target) if datastore['SEARCH_GOOGLE']
		emails << search_bing(target) if datastore['SEARCH_BING']
		emails << search_yahoo(target) if datastore['SEARCH_YAHOO']
		emails.flatten!
		emails.uniq!
		emails.sort!

		print_status("Located #{emails.length} email addresses for #{target}")
		emails.each do |e|
			print_status("\t#{e.to_s}")
		end

		write_output(emails.join("\n")) if datastore['OUTFILE']
	end
end
