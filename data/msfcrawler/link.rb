
##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

# $Revision: 9212 $

require 'rubygems'
require 'pathname'
require 'nokogiri'
require 'uri'

class CrawlerLink < BaseParser

  def parse(request,result)
    return unless result['Content-Type'].include?('text/html')

    doc = Nokogiri::HTML(result.body.to_s)
    doc.css('link').each do |link|
      hr = link['href']
      if hr && !hr.match(/^(\#|javascript\:)/)
        begin
          hreq = urltohash('GET', hr, request['uri'], nil)
          insertnewpath(hreq)
        rescue URI::InvalidURIError
        end
      end

    end
  end
end

