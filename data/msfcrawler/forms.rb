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

class CrawlerForms < BaseParser

  def parse(request,result)

    if !result['Content-Type'].include? "text/html"
      return
    end

    hr = ''
    m = ''

    doc = Nokogiri::HTML(result.body.to_s)
    doc.css('form').each do |f|
      hr = f['action']

      fname = f['name']
      fname = "NONE" if fname.empty?

      m = f['method'].empty? ? 'GET' : f['method'].upcase

      htmlform = Nokogiri::HTML(f.inner_html)

      arrdata = []

      htmlform.css('input').each do |p|
        arrdata << "#{p['name']}=#{Rex::Text.uri_encode(p['value'])}"
      end

      data = arrdata.join("&").to_s

      begin
        hreq = urltohash(m, hr, request['uri'], data)
        hreq['ctype'] = 'application/x-www-form-urlencoded'
        insertnewpath(hreq)
      rescue URI::InvalidURIError
      end
    end
  end
end

