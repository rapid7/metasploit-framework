require 'rubygems'
require 'pathname'
require 'hpricot'
require 'uri'

class CrawlerForms < BaseParser

	def parse(request,result)
		
		if !result['Content-Type'].include? "text/html"
			return
		end
		
		hr = ''
		m = ''

		doc = Hpricot(result.body.to_s)
		doc.search('form').each do |f|
			hr = f.attributes['action']

			fname = f.attributes['name']
			if fname.empty?
				fname = "NONE"
			end  

			m = "GET"
			if !f.attributes['method'].empty?
				m = f.attributes['method'].upcase
			end
			
			#puts "Parsing form name: #{fname} (#{m})"		
			
			htmlform = Hpricot(f.inner_html)
			
			arrdata = []
			
			htmlform.search('input').each do |p|
				#puts p.attributes['name']
				#puts p.attributes['type']
				#puts p.attributes['value']
				
				#raw_request has uri_encoding disabled as it encodes '='. 
				arrdata << (p.attributes['name'] + "=" + Rex::Text.uri_encode(p.attributes['value']))				
			end
			
			data = arrdata.join("&").to_s
	
		
			begin
				uri = URI.parse(hr)
			
				tssl = false
				if uri.scheme == "https"
					tssl = true
				else
					tssl = false
				end

				if !uri.host or uri.host == nil
					thost = request['rhost']
					tssl = self.targetssl	
				else
					thost = uri.host	
				end

				if !uri.port or uri.port == nil
					tport = request['rport']
				else
					tport = uri.port
				end

				if !uri.path or uri.path == nil
					tpath = "/"
				else
					tpath = uri.path
				end
				
				newp = Pathname.new(tpath)
				oldp = Pathname.new(request['uri'])
				if !oldp.absolute?
					if !newp.absolute?
						newp = oldp + newp.cleanpath
					end
				end
				
				hreq = {
					'rhost'		=> thost,
					'rport'		=> tport,
					'uri'  		=> newp.to_s,
					'method'   	=> m,
					'ctype'		=> 'application/x-www-form-urlencoded',
					'ssl'		=> tssl,
					'query'		=> m == 'GET'? data : uri.query,
					'data'		=> m == 'GET'? nil : data
					
				}
				#puts hreq
				insertnewpath(hreq)
			
					
			rescue URI::InvalidURIError
				#puts "Parse error"
				#puts "Error: #{link[0]}"
			end
		end			
	end 
end

