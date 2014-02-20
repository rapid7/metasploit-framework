
##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

# $Revision: 9212 $

require 'rubygems'
require 'pathname'
require 'hpricot'
require 'uri'

class CrawlerImage < BaseParser

  def parse(request,result)

    if !result['Content-Type'].include? "text/html"
      return
    end

    doc = Hpricot(result.body.to_s)
    doc.search('img').each do |i|

    im = i.attributes['src']

    if im and !im.match(/^(\#|javascript\:)/)
      begin
        hreq = urltohash('GET',im,request['uri'],nil)

        insertnewpath(hreq)

      rescue URI::InvalidURIError
        #puts "Parse error"
        #puts "Error: #{i[0]}"
      end
    end
    end
  end
end

