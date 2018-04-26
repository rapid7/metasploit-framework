##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'pathname'
require 'nokogiri'
require 'uri'

class CrawlerComments < BaseParser

  def parse(request,result)
    return unless result['Content-Type'].include?('text/html')

    doc = Nokogiri::HTML(result.body.to_s)
    doc.xpath('//comment()').each do |comment|
      # searching for href
      hr = /href\s*=\s*"([^"]*)"/.match(comment)
      if hr
        begin
          hreq = urltohash('GET', hr[1], request['uri'], nil)
          insertnewpath(hreq)
        rescue URI::InvalidURIError
          # ignored
        end
      end

    end

  end
end
