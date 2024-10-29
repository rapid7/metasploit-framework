##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'pathname'
require 'nokogiri'
require 'uri'

class CrawlerSimple < BaseParser

  def parse(request,result)
    return unless result['Content-Type'].include?('text/html')

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

