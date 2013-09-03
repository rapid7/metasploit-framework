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
			'Name' => 'Archive.org Stored Domain URLs',
			'Description' => %q{
					This module pulls and parses the URLs stored by Archive.org for the purpose of
				replaying during a web assessment. Finding unlinked and old pages.
			},
			'Author' => [ 'mubix' ],
			'License' => MSF_LICENSE
		))
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
		pages = []
		header = { 'User-Agent' => "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/525.13 (KHTML, like Gecko) Chrome/4.0.221.6 Safari/525.13"}
		clnt = Net::HTTP::Proxy(@proxysrv,@proxyport,@proxyuser,@proxypass).new("wayback.archive.org")
		resp = clnt.get2("/web/*/http://"+targetdom+"/*",header)
		response << resp.body
		response.each_line do |line|
			pages << line.gsub!(/(.+>)(.+)(<\/a>)\n/, '\2')
		end

		pages.delete_if{|x| x==nil}
		pages.uniq!
		pages.sort!

		for i in (0..(pages.count-1))
			fix = "http://" + pages[i].to_s
			pages[i] = fix
		end
		return pages
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
		print_status("Pulling urls from Archive.org")
		urls = pull_urls(target)

		print_status("Located #{urls.count} addresses for #{target}")

		if datastore['OUTFILE']
			write_output(urls.join("\n") + "\n")
		else
			urls.each do |i|
				print_line(i)
			end
		end
	end
end
