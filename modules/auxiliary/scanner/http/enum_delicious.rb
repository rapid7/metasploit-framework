##
# $Id$
##

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
			'Name' => 'Pull Del.icio.us Links (URLs) for a domain',
			'Description' => %q{
					This module pulls and parses the URLs stored by Del.icio.us users for the
				purpose of replaying during a web assessment. Finding unlinked and old pages.
			},
			'Author' => [ 'Rob Fuller <mubix [at] hak5.org>' ],
			'License' => MSF_LICENSE,
			'Version' => '$Revision$'))

		register_options(
			[
				OptString.new('DOMAIN', [ true, "Domain to request URLS for"]),
				OptString.new('OUTFILE', [ false, "Where to output the list for use"])
			], self.class)

		register_advanced_options(
			[
				OptString.new('PROXY', [ false, "Proxy server to route connection. <host>:<port>",nil]),
				OptString.new('PROXY_USER', [ false, "Proxy Server User",nil]),
				OptString.new('PROXY_PASS', [ false, "Proxy Server Password",nil])
			], self.class)

	end

	def pull_urls(targetdom)
		response = ""
		list = []
		lastpage = 0
		pagenum = 1
		while lastpage == 0
			print_status("Page number: " + pagenum.to_s)
			header = { 'User-Agent' => "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/525.13 (KHTML, like Gecko) Chrome/4.0.221.6 Safari/525.13"}
			clnt = Net::HTTP::Proxy(@proxysrv,@proxyport,@proxyuser,@proxypass).new("www.delicious.com")
			resp = clnt.get2("/search?p=site%3A"+targetdom+"&page="+pagenum.to_s,header)
			response << resp.body
			response.each_line do |line|
				list << line.gsub!(/(.+<a rel=\"nofollow)(.+=+\")(.+)(\".+)/, '\3')
			end
			if /pn\ next/.match(data)
				pagenum += 1
			else
				lastpage = 1
			end
		end

		list.delete_if{|x| x==nil}
		list.uniq!
		list.sort!

		return list
	end

	def write_output(data)
		print_status("Writing URLs list to #{datastore['OUTFILE']}...")
		file_name = datastore['OUTFILE']
		if FileTest::exist?(file_name)
			print_status("OUTFILE already existed, appending..")
		else
			print_status("OUTFILE did not exist, creating..")
		end

		File.open(file_name, 'ab') do |fd|
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

		target = datastore['DOMAIN']

		urls = []
		print_status("Pulling urls from Delicious.com")
		urls = pull_urls(target)

		print_status("Located #{urls.count} addresses for #{target}")

		if datastore['OUTFILE']
			write_output(urls.join)
		else
			urls.each do |i|
				print_status(i)
			end
		end
	end
end
