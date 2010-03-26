require 'rubygems'
require 'pathname'
require 'hpricot'
require 'uri'

class CrawlerForms < BaseParser

	def parse(request,result)
		
		if !result['Content-Type'].include? "text/html"
			return
		end

		doc = Hpricot(result.body.to_s)
		doc.search('form').each do |f|
			#puts f.attributes['action']
			#puts f.attributes['name']
			#puts f.attributes['method']
	
			htmlform = Hpricot(f.inner_html)
			htmlform.search('input').each do |p|
				#puts p.attributes['name']
				#puts p.attributes['type']
				#puts p.attributes['value']
			end
		end
		
	end 
end

