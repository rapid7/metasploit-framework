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

class CrawlerObjects < BaseParser

  def parse(request,result)
    return unless result['Content-Type'].include?('text/html') # TOOD: use MIXIN
    hr = ''
    m = ''
    doc = Nokogiri::HTML(result.body.to_s)
    doc.xpath("//object/embed").each do |obj|
      s = obj['src']
      begin
        hreq = urltohash('GET', s, request['uri'], nil)
        insertnewpath(hreq)
      rescue URI::InvalidURIError
      end
    end
  end

end

