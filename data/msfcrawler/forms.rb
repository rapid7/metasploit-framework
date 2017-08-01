##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'pathname'
require 'nokogiri'
require 'uri'

class CrawlerForms < BaseParser

  def parse(request,result)
    return unless result['Content-Type'].include?('text/html')

    doc = Nokogiri::HTML(result.body.to_s)
    doc.css('form').each do |f|
      hr = f['action']

      # Removed because unused
      #fname = f['name']
      #fname = 'NONE' if fname.empty?

      m = (f['method'].empty? ? 'GET' : f['method'].upcase)

      arrdata = []

      f.css('input').each do |p|
        arrdata << "#{p['name']}=#{Rex::Text.uri_encode(p['value'])}"
      end

      data = arrdata.join("&").to_s

      begin
        hreq = urltohash(m, hr, request['uri'], data)
        hreq['ctype'] = 'application/x-www-form-urlencoded'
        insertnewpath(hreq)
      rescue URI::InvalidURIError
        #puts "Parse error"
        #puts "Error: #{link[0]}"
      end

    end
  end
end

