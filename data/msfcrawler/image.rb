##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'pathname'
require 'nokogiri'
require 'uri'

class CrawlerImage < BaseParser

  def parse(request,result)

    return unless result['Content-Type'].include?('text/html')

    doc = Nokogiri::HTML(result.body.to_s)
    doc.css('img').each do |i|
      im = i['src']
      if im && !im.match(/^(\#|javascript\:)/)
        begin
          hreq = urltohash('GET', im, request['uri'], nil)
          insertnewpath(hreq)
        rescue URI::InvalidURIError
          # ignored
        end
      end

    end
  end
end

