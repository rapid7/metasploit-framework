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

class CrawlerObjects < BaseParser

  def parse(request,result)

    if !result['Content-Type'].include? "text/html"
      return
    end

    hr = ''
    m = ''

    doc = Hpricot(result.body.to_s)
    doc.search("//object/embed").each do |obj|

      s = obj['src']

      begin
        hreq = urltohash('GET',s,request['uri'],nil)

        insertnewpath(hreq)


      rescue URI::InvalidURIError
        #puts "Parse error"
        #puts "Error: #{link[0]}"
      end
    end
  end
end

