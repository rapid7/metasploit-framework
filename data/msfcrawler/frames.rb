##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

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
          # ignored
        end
      end

    end
  end

end

