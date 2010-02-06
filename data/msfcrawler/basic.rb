require 'rubygems'
require 'pathname'
require 'uri'

class CrawlerBasic < BaseParser

	def parse(request,result)
		
		#puts "R: #{result.body}"
		
		links = result.body.to_s.scan(/href\s*=\s*[\"\'](.+?)[\"\']/)  
		
		links.each do |link| 
			begin
				uri = URI.parse(link[0])
			
				tssl = false
				if uri.scheme == "https"
					tssl = true
				else
					tssl = false
				end

				if !uri.host or uri.host == nil
					thost = request['rhost']	
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
				if !newp.absolute?
					oldp = Pathname.new(request['uri'])
					newp = oldp + newp.cleanpath
				end
				

				hreq = {
					'rhost'		=> thost,
					'rport'		=> tport,
					'uri'  		=> newp.to_s,
					'method'   	=> 'GET',
					'ctype'		=> 'text/plain',
					'ssl'		=> tssl,
					'query'		=> uri.query
					
				}
				#puts "R: #{hreq['uri']}"
				insertnewpath(hreq)
					
		rescue URI::InvalidURIError
				#puts "Parse error"
				#puts "Error: #{link[0]}"
			end
		end
	end 
end

