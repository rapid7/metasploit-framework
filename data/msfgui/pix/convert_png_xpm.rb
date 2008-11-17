dir = Dir.open(".")
dir.entries.each do |ent|
	next if ent !~ /\.png$/
	xpm = ent.sub(".png", ".xpm")
	
	raw = ""
	
	system("rm -f #{xpm} #{xpm}.gz")
	system("convert #{ent} #{xpm}")
	
	File.readlines(xpm).each do |line|
		line.strip!
		next if line !~ /^\"/
		raw << line.gsub(/^\"|\",?$/, '') + "\n"
	end
	
	fd = File.open(xpm, "wb")
	fd.write(raw)
	fd.close
	
	system("gzip -9 #{xpm}")
end
