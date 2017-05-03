##
# $Id $
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
      'Name' => 'Search URL Collector',
      'Description' => %q{
        This module uses Google to create a list of
        URLs for the given search query keywords.
      },
      'Author' => [ 'Mario Schmidt <mario.schmidt[at]msware.net>' ],
      'License' => MSF_LICENSE,
      'Version' => '$Revision: $'))

    register_options(
      [
        OptString.new('QUERY', [ true, "The query keywords"]),
        OptBool.new('SEARCH_GOOGLE', [ true, 'Enable Google as a backend search engine', true]),
        OptString.new('OUTFILE', [ false, "A filename to store the generated URL list"]),

      ], self.class)

    register_advanced_options(
      [
        OptString.new('PROXY', [ false, "Proxy server to route connection. <host>:<port>",nil]),
        OptString.new('PROXY_USER', [ false, "Proxy Server User",nil]),
        OptString.new('PROXY_PASS', [ false, "Proxy Server Password",nil])
      ], self.class)

  end

  def search_google(query)
    print_status("Searching Google for '#{query}'")
    links = []
    page = 1
    start = 100
    lastpage = false
    header = { 'User-Agent' => "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"}
    clnt = Net::HTTP::Proxy(@proxysrv,@proxyport,@proxyuser,@proxypass).new("www.google.com")
    while !lastpage
      resp = clnt.get2("/search?hl=en&lr=&ie=UTF-8&q="+URI.escape(query)+"&start=#{start}&sa=N&filter=0&num=100",header)      
      page_links = []
      resp.body.scan(/url\?q=([^&]*)/) do |t|        
        page_links << URI.unescape(t[0].to_s) if t.length > 0
      end
      links << page_links
      links.flatten!
      print_status("Found #{page_links.length} URL on result page #{page}, #{links.length} URL total")
      lastpage = resp.body.scan(/>Next<\/span>/).length == 0
      page = page + 1
      start = start + 100
    end
    return links
  end

  def write_output(data)
    print_status("Writing URL list to #{datastore['OUTFILE']}...")
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

    query = datastore['QUERY']

    links = []
    links << search_google(query) if datastore['SEARCH_GOOGLE']
    links.flatten!
    links.uniq!
    links.sort!
    
    print_status("Found #{links.length} URL for '#{query}'")
    links.each do |l|
      print_status("\t#{l}")
    end

    write_output(links.join("\n")) if datastore['OUTFILE']
  end
end
