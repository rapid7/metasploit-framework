require 'rubygems'
require 'pathname'
require 'uri'


$flarebinary = "/home/et/Downloads/flare"
$flareoutdir = "/home/et/Downloads/"

class CrawlerFlash < BaseParser


	def parse(request,result)
		rexp = ['loadMovieNum\(\'(.*?)\'',
			'loadMovie\(\'(.*?)\'',
			'getURL\(\'(.*?)\''
			]		

		
		if !result['Content-Type'].include? "application/x-shockwave-flash"
			return
		end
		
		outswf = File.join($flareoutdir,request['uri'].gsub(/\//,'_'))
		
		puts "Downloading SWF file to: #{outswf}" 
		
		ffile = File.new(outswf, "wb")    
		ffile.puts(result.body)
		ffile.close		

		system("#{$flarebinary} #{outswf}")
		
		outflr = outswf.gsub('.swf','.flr')
		
		if File.exists?(outflr)
			puts "Decompiled SWF file to: #{outflr}" 	
		else
			puts "Error: Decompilation failed."
			return
		end
		
		File.open(outflr, "r") do |infile|
			while (line = infile.gets)

			rexp.each do |r|						
				links = line.to_s.scan(Regexp.new(r,true)) #" 
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
						if !newp.absolute?
							if oldp.to_s[-1,1] == '/'
								newp = oldp+newp
							else
								if !newp.to_s.empty?
									newp = File.join(oldp.dirname,newp)
								end
							end		
						end

						hreq = {
							'rhost'		=> thost,
							'rport'		=> tport,
							'uri'  		=> newp.to_s,
							'method'   	=> 'GET',
							'ctype'		=> 'text/plain',
							'ssl'		=> tssl,
							'query'		=> uri.query,
							'data'		=> nil
						}
				
					
						insertnewpath(hreq)
					
					rescue URI::InvalidURIError
						#puts "Parse error"
						#puts "Error: #{link[0]}"
					end
				end	
			end
			end
		end										
	end 
end

