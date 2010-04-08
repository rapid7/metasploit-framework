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
						hreq = urltohash('GET',link[0],request['uri'],nil)

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

