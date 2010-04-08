require 'rubygems'
require 'pathname'
require 'hpricot'
require 'uri'

class CrawlerSimple < BaseParser

	def parse(request,result)
		
		if !result['Content-Type'].include? "text/html"
			return
		end
		
		doc = Hpricot(result.body.to_s)
		doc.search('a').each do |link|
		
		hr = link.attributes['href']
		
		if hr and !hr.match(/^(\#|javascript\:)/) 
			begin
				hreq = urltohash('GET',hr,request['uri'],nil)				
				
				insertnewpath(hreq)
					
			rescue URI::InvalidURIError
				#puts "Parse error"
				#puts "Error: #{link[0]}"
			end
		end
		end
	end 
end

