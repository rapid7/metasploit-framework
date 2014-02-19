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
require 'hpricot'
require 'uri'

class CrawlerForms < BaseParser

  def parse(request,result)

    if !result['Content-Type'].include? "text/html"
      return
    end

    hr = ''
    m = ''

    doc = Hpricot(result.body.to_s)
    doc.search('form').each do |f|
      hr = f.attributes['action']

      fname = f.attributes['name']
      if fname.empty?
        fname = "NONE"
      end

      m = "GET"
      if !f.attributes['method'].empty?
        m = f.attributes['method'].upcase
      end

      #puts "Parsing form name: #{fname} (#{m})"

      htmlform = Hpricot(f.inner_html)

      arrdata = []

      htmlform.search('input').each do |p|
        #puts p.attributes['name']
        #puts p.attributes['type']
        #puts p.attributes['value']

        #raw_request has uri_encoding disabled as it encodes '='.
        arrdata << (p.attributes['name'] + "=" + Rex::Text.uri_encode(p.attributes['value']))
      end

      data = arrdata.join("&").to_s


      begin
        hreq = urltohash(m,hr,request['uri'],data)

        hreq['ctype'] = 'application/x-www-form-urlencoded'

        insertnewpath(hreq)


      rescue URI::InvalidURIError
        #puts "Parse error"
        #puts "Error: #{link[0]}"
      end
    end
  end
end

