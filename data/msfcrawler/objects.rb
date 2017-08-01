##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'pathname'
require 'nokogiri'
require 'uri'

class CrawlerObjects < BaseParser

  def parse(request,result)
    return unless result['Content-Type'].include?('text/html') # TOOD: use MIXIN
    hr = ''
    m = ''
    doc = Nokogiri::HTML(result.body.to_s)
    doc.xpath("//object/embed").each do |obj|
      s = obj['src']
      begin
        hreq = urltohash('GET', s, request['uri'], nil)
        insertnewpath(hreq)
      rescue URI::InvalidURIError
        # ignored
      end
    end
  end

end

