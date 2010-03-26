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
			puts "Parsing form: #{f.attributes['name']}"
			
			m = "GET"
			if f.attributes['method']
				m = f.attributes['method']
			end
	
			htmlform = Hpricot(f.inner_html)
			
			arrdata = []
			
			htmlform.search('input').each do |p|
				#puts p.attributes['name']
				#puts p.attributes['type']
				#puts p.attributes['value']
				arrdata << (p.attributes['name'] + "=" + p.attributes['value'])				
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
					'ctype'		=> 'text/plain',
					'ssl'		=> tssl,
					'query'		=> uri.query,
					'data'		=> data
					
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

