require 'rubygems'
require 'pathname'
require 'hpricot'
require 'uri'

class CrawlerScripts < BaseParser

	def parse(request,result)
		
		if !result['Content-Type'].include? "text/html"
			return
		end
		
		hr = ''
		m = ''

		doc = Hpricot(result.body.to_s)
		doc.search("//script").each do |obj|

			s = obj['src']

			begin
				hreq = urltohash('GET',s,request['uri'],nil)				
				
				insertnewpath(hreq)
			
					
			rescue URI::InvalidURIError
				#puts "Parse error"
				#puts "Error: #{link[0]}"
			end
		end			
	end 
end

