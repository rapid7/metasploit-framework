##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##
require 'msf/core'
require 'anemone/http'


class Metasploit3 < Msf::Auxiliary

  include Msf::Auxiliary::Report
  
	def initialize
		super(
			'Name'        => 'VHOST finder using Bing.',
			'Description' => %q{Find all VHOST's belongs to particular IP(s) using Bing.
                         Without setting BING_API_KEY module makes simple query to bing.com and parses results.
                         Keep in mind that returned results from Bing API are usually limited compare to these
                         obtained from bing.com},
			'Version'       => '$Revision:$',
			'Author'      => 'Marcin \'Icewall\' Noga <martin[at]hispasec.com>',
			'License'     => MSF_LICENSE
		)

    register_options(
      [
				OptAddressRange.new('IPRANGE',[true,'The IP or address range for which you want to check vhosts.','']),
        OptString.new('BING_API_KEY',[false,'Set Bing API Key to use API interface.','']),
        OptBool.new('FULL_URL',[false,'Display all found URLs related with specific IP(s). When this option is set to false only domains will be displayed.',false])
      ],self.class)    
	end

  def init()
    @vhosts = [] #array contains found vhosts
    @key = datastore['BING_API_KEY']
    @offset = 0
    if @key.empty? #Simple Bing search settings
      @amount = 10 #amount of results per page (in this mode without setting special cookie u can't increase this value)
      @url = "http://www.bing.com/search?q=ip:%s&first=%d" #base url
      @rule = /<h3><a href="(.*?)"/ #rule to catch all urls related with our query
    else #Bing_api settings
      @amount = 50
      @url = "http://api.bing.net/xml.aspx?AppId=%s&Verstion=2.2&Query=ip:%s&Sources=web&web.count=%d&web.offset=%d"
      @rule = /<web:Url>(.*?)<\/web:Url>/
    end                              
  end
				
	def run()
    init()
		ip_range = Rex::Socket::RangeWalker.new(datastore['IPRANGE'])
		while(true)
			@ip = ip_range.next_ip()
			break if not @ip
			find_vhosts()
			#check whether result should only contains domains
			remove_duplicates() if not datastore['FULL_URL']
			print_status("VHOSTS for #{@ip}:")
			#sort results and report them
			@vhosts.sort!.each do |item|
				print_good(item)
				uri = URI(URI.encode(item))
				report_web_site(
					:host	=> @ip,
					:vhost => uri.host,
					:port	=> uri.port
				)
			end
			reset()
		end
  end

  def find_vhosts()
    http = Anemone::HTTP.new()
    begin
      page = http.fetch_page( get_url() )
      @vhosts += page.body.scan(@rule)
    end while (next?(page.body))
    #just make sure vhosts array is flat
    return @vhosts.flatten!
  end
 
  def next?(body)
    if @key.empty?
      flag = body.include?("class=\"sb_pagN\"")#simple check whether 'Next' page url exists
    else
      total = body.match(/<web:Total>(.*?)<\/web:Total>/)[1].to_i
      flag =  (total > @offset + @amount)
    end
    @offset += @amount
    return flag
  end

  def remove_duplicates()
    @vhosts = @vhosts.collect do |url|		
			uri = URI(URI.encode(url)) #encode url first to avoid errors
			"%s://%s" % [uri.scheme,uri.host]
		end
		#we are interested only in uniq domains
		@vhosts.uniq!
  end
  
  def get_url()
    if @key.empty?#return proper url for simple search
      return @url % [@ip,@offset]
    end
    #return proper url for Bing_api
    return @url % [@key,@ip,@amount,@offset]
  end
  def reset()
		@vhosts.clear()
		@offset = 0
	end
end
 