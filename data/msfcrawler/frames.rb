
##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##


require 'rubygems'
require 'pathname'
require 'hpricot'
require 'uri'

class CrawlerFrames < BaseParser

  def parse(request,result)

    if !result['Content-Type'].include? "text/html"
      return
    end

    doc = Hpricot(result.body.to_s)
    doc.search('iframe').each do |ifra|

    ir = ifra.attributes['src']

    if ir and !ir.match(/^(\#|javascript\:)/)
      begin
        hreq = urltohash('GET',ir,request['uri'],nil)

        insertnewpath(hreq)

      rescue URI::InvalidURIError
        #puts "Error"
      end
    end
    end
  end
end

