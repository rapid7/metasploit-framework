##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

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
          # ignored
        end
      end

    end
  end
end

