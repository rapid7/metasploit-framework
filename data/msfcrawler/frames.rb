
##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##


require 'rubygems'
require 'pathname'
require 'nokogiri'
require 'uri'

class CrawlerFrames < BaseParser

  def parse(request,result)

    return unless result['Content-Type'].include?('text/html')

    doc = Nokogiri::HTML(result.body.to_s)
    doc.css('iframe').each do |ifra|
      ir = ifra['src']

      if ir && !ir.match(/^(\#|javascript\:)/)
        begin
          hreq = urltohash('GET', ir, request['uri'], nil)
          insertnewpath(hreq)
        rescue URI::InvalidURIError
        end
      end

    end
  end

end

