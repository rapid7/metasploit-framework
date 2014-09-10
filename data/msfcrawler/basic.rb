##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

# $Revision$

require 'rubygems'
require 'pathname'
require 'nokogiri'
require 'uri'

class CrawlerSimple < BaseParser

  def parse(request,result)

    if !result['Content-Type'].include? "text/html"
      return
    end

    # doc = Hpricot(result.body.to_s)
    doc = Nokogiri::HTML(result.body.to_s)
    doc.css('a').each do |anchor_tag|
      hr = anchor_tag['href']
      if hr && !hr.match(/^(\#|javascript\:)/)
        begin
          hreq = urltohash('GET', hr, request['uri'], nil)
          insertnewpath(hreq)
        rescue URI::InvalidURIError
          #puts "Parse error"
          #puts "Error: #{link[0]}"
        end
      end
    end
  end
end

