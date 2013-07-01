#!/usr/bin/env ruby
#
# Check (recursively) for style compliance violations and other
# tree inconsistencies.
#
# by jduck and friends
#

CHECK_OLD_RUBIES = !!ENV['MSF_CHECK_OLD_RUBIES']

if CHECK_OLD_RUBIES
	require 'rvm'
	warn "This is going to take a while, depending on the number of Rubies you have installed."
end

class String
	def red
		"\e[1;31;40m#{self}\e[0m"
	end

	def yellow
		"\e[1;33;40m#{self}\e[0m"
	end

	def ascii_only?
		self =~ Regexp.new('[\x00-\x08\x0b\x0c\x0e-\x19\x7f-\xff]', nil, 'n') ? false : true
	end
end

class Msftidy

	LONG_LINE_LENGTH = 200 # From 100 to 200 which is stupidly long

	def initialize(source_file)
		@source  = load_file(source_file)
		@name    = source_file
	end

	public

	##
	#
	# The following two functions only print what you throw at them,
	# with the option of displying the line number.  error() is meant
	# for mistakes that might actually break something.
	#
	##

	def warn(txt, line=0)
		line_msg = (line>0) ? ":#{line.to_s}" : ''
		puts "#{@name}#{line_msg} - [#{'WARNING'.yellow}] #{txt}"
	end

	def error(txt, line=0)
		line_msg = (line>0) ? ":#{line.to_s}" : ''
		puts "#{@name}#{line_msg} - [#{'ERROR'.red}] #{txt}"
	end


	##
	#
	# The functions below are actually the ones checking the source code
	#
	##

	def check_ref_identifiers
		in_super = false
		in_refs  = false

		@source.each_line do |line|
			if !in_super and line =~ /[\n\t]+super\(/
				in_super = true
			elsif in_super and line =~ /[[:space:]]*def \w+[\(\w+\)]*/
				in_super = false
				break
			end

			if in_super and line =~ /'References'[[:space:]]*=>/
				in_refs = true
			elsif in_super and in_refs and line =~ /^[[:space:]]+\],*/m
				break
			elsif in_super and in_refs and line =~ /[^#]+\[[[:space:]]*['"](.+)['"][[:space:]]*,[[:space:]]*['"](.+)['"][[:space:]]*\]/
				identifier = $1.strip.upcase
				value      = $2.strip

				case identifier
				when 'CVE'
					warn("Invalid CVE format: '#{value}'") if value !~ /^\d{4}\-\d{4}$/
				when 'OSVDB'
					warn("Invalid OSVDB format: '#{value}'") if value !~ /^\d+$/
				when 'BID'
					warn("Invalid BID format: '#{value}'") if value !~ /^\d+$/
				when 'MSB'
					warn("Invalid MSB format: '#{value}'") if value !~ /^MS\d+\-\d+$/
				when 'MIL'
					warn("milw0rm references are no longer supported.")
				when 'EDB'
					warn("Invalid EDB reference") if value !~ /^\d+$/
				when 'WVE'
					warn("Invalid WVE reference") if value !~ /^\d+\-\d+$/
				when 'US-CERT-VU'
					warn("Invalid US-CERT-VU reference") if value !~ /^\d+$/
				when 'URL'
					if value =~ /^http:\/\/www\.osvdb\.org/
						warn("Please use 'OSVDB' for '#{value}'")
					elsif value =~ /^http:\/\/cvedetails\.com\/cve/
						warn("Please use 'CVE' for '#{value}'")
					elsif value =~ /^http:\/\/www\.securityfocus\.com\/bid\//
						warn("Please use 'BID' for '#{value}'")
					elsif value =~ /^http:\/\/www\.microsoft\.com\/technet\/security\/bulletin\//
						warn("Please use 'MSB' for '#{value}'")
					elsif value =~ /^http:\/\/www\.exploit\-db\.com\/exploits\//
						warn("Please use 'EDB' for '#{value}'")
					elsif value =~ /^http:\/\/www\.wirelessve\.org\/entries\/show\/WVE\-/
						warn("Please use 'WVE' for '#{value}'")
					elsif value =~ /^http:\/\/www\.kb\.cert\.org\/vuls\/id\//
						warn("Please use 'US-CERT-VU' for '#{value}'")
					end
				end
			end
		end
	end

	def check_old_keywords
		max_count = 10
		counter   = 0
		if @source =~ /^##/
			@source.each_line do |line|
				# If exists, the $Id$ keyword should appear at the top of the code.
				# If not (within the first 10 lines), then we assume there's no
				# $Id$, and then bail.
				break if counter >= max_count

				if line =~ /^#[[:space:]]*\$Id\$/i
					warn("Keyword $Id$ is no longer needed.")
					break
				end

				counter += 1
			end
		end

		if @source =~ /'Version'[[:space:]]*=>[[:space:]]*['"]\$Revision\$['"]/
			warn("Keyword $Revision$ is no longer needed.")
		end
	end

	def check_verbose_option
		if @source =~ /Opt(Bool|String).new\([[:space:]]*('|")VERBOSE('|")[[:space:]]*,[[:space:]]*\[[[:space:]]*/
			warn("VERBOSE Option is already part of advanced settings, no need to add it manually.")
		end
	end

	def check_badchars
		badchars = %Q|&<=>|

		in_super   = false
		in_author  = false

		@source.each_line do |line|
			#
			# Mark our "super" code block
			#
			if !in_super and line =~ /[\n\t]+super\(/
				in_super = true
			elsif in_super and line =~ /[[:space:]]*def \w+[\(\w+\)]*/
				in_super = false
				break
			end

			#
			# While in super() code block
			#
			if in_super and line =~ /'Name'[[:space:]]*=>[[:space:]]*['|"](.+)['|"]/
				# Now we're checking the module titlee
				mod_title = $1
				mod_title.each_char do |c|
					if badchars.include?(c)
						error("'#{c}' is a bad character in module title.")
					end
				end

				if not mod_title.ascii_only?
					error("Please avoid unicode or non-printable characters in module title.")
				end

				# Since we're looking at the module title, this line clearly cannot be
				# the author block, so no point to run more code below.
				next
			end

			#
			# Mark our 'Author' block
			#
			if in_super and !in_author and line =~ /'Author'[[:space:]]*=>/
				in_author = true
			elsif in_super and in_author and line =~ /\],*\n/ or line =~ /['"][[:print:]]*['"][[:space:]]*=>/
				in_author = false
			end


			#
			# While in 'Author' block, check for Twitter handles
			#
			if in_super and in_author
				if line =~ /Author/
					author_name = line.scan(/\[[[:space:]]*['"](.+)['"]/).flatten[-1] || ''
				else
					author_name = line.scan(/['"](.+)['"]/).flatten[-1] || ''
				end

				if author_name =~ /^@.+$/
					error("No Twitter handles, please. Try leaving it in a comment instead.")
				end

				if not author_name.ascii_only?
					error("Please avoid unicode or non-printable characters in Author")
				end
			end
		end
	end

	def check_extname
		if File.extname(@name) != '.rb'
			error("Module should be a '.rb' file, or it won't load.")
		end
	end

	def test_old_rubies(f_rel)
		return true unless CHECK_OLD_RUBIES
		return true unless Object.const_defined? :RVM
		puts "Checking syntax for #{f_rel}."
		rubies ||= RVM.list_strings
		res = %x{rvm all do ruby -c #{f_rel}}.split("\n").select {|msg| msg =~ /Syntax OK/}
		error("Fails alternate Ruby version check") if rubies.size != res.size
	end

	def check_ranking
		return if @source !~ / \< Msf::Exploit/

		available_ranks = [
			'ManualRanking',
			'LowRanking',
			'AverageRanking',
			'NormalRanking',
			'GoodRanking',
			'GreatRanking',
			'ExcellentRanking'
		]

		if @source =~ /Rank \= (\w+)/
			if not available_ranks.include?($1)
				error("Invalid ranking. You have '#{$1}'")
			end
		end
	end

	def check_disclosure_date
		return if @source =~ /Generic Payload Handler/ or @source !~ / \< Msf::Exploit/

		# Check disclosure date format
		if @source =~ /'DisclosureDate'.*\=\>[\x0d\x20]*['\"](.+)['\"]/
			d = $1  #Captured date
			# Flag if overall format is wrong
			if d =~ /^... \d{1,2}\,* \d{4}/
				# Flag if month format is wrong
				m = d.split[0]
				months = [
					'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
					'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'
				]

				error('Incorrect disclosure month format') if months.index(m).nil?
			else
				error('Incorrect disclosure date format')
			end
		else
			error('Exploit is missing a disclosure date')
		end
	end

	def check_title_casing
		if @source =~ /'Name'[[:space:]]*=>[[:space:]]*['"](.+)['"],*$/
			words = $1.split
			words.each do |word|
				if %w{and or the for to in of as with a an on at via}.include?(word)
					next
				elsif %w{pbot}.include?(word)
				elsif word =~ /^[a-z]+$/
					warn("Suspect capitalization in module title: '#{word}'")
				end
			end
		end
	end

	def check_bad_terms
		# "Stack overflow" vs "Stack buffer overflow" - See explanation:
		# http://blogs.technet.com/b/srd/archive/2009/01/28/stack-overflow-stack-exhaustion-not-the-same-as-stack-buffer-overflow.aspx
		if @source =~ /class Metasploit\d < Msf::Exploit::Remote/ and @source.gsub("\n", "") =~ /stack[[:space:]]+overflow/i
			warn('Contains "stack overflow" You mean "stack buffer overflow"?')
		elsif @source =~ /class Metasploit\d < Msf::Auxiliary/ and @source.gsub("\n", "") =~ /stack[[:space:]]+overflow/i
			warn('Contains "stack overflow" You mean "stack exhaustion"?')
		end
	end

	def check_function_basics
		functions = @source.scan(/def (\w+)\(*(.+)\)*/)

		functions.each do |func_name, args|
			# Check argument length
			args_length = args.split(",").length
			warn("Poorly designed argument list in '#{func_name}()'. Try a hash.") if args_length > 6
		end
	end

	def check_lines
		url_ok     = true
		no_stdio   = true
		in_comment = false
		in_literal = false
		src_ended  = false
		idx        = 0

		@source.each_line { |ln|
			idx += 1

			# block comment awareness
			if ln =~ /^=end$/
				in_comment = false
				next
			end
			in_comment = true if ln =~ /^=begin$/
			next if in_comment

			# block string awareness (ignore indentation in these)
			in_literal = false if ln =~ /^EOS$/
			next if in_literal
			in_literal = true if ln =~ /\<\<-EOS$/

			# ignore stuff after an __END__ line
			src_ended = true if ln =~ /^__END__$/
			next if src_ended

			if ln =~ /[\x00-\x08\x0b\x0c\x0e-\x19\x7f-\xff]/
				error("Unicode detected: #{ln.inspect}", idx)
			end

			if (ln.length > LONG_LINE_LENGTH)
				warn("Line exceeding #{LONG_LINE_LENGTH.to_s} bytes", idx)
			end

			if ln =~ /[ \t]$/
				warn("Spaces at EOL", idx)
			end

			if (ln.length > 1) and (ln =~ /^([\t ]*)/) and ($1.include?(' '))
				warn("Bad indent: #{ln.inspect}", idx)
			end

			if ln =~ /\r$/
				warn("Carriage return EOL", idx)
			end

			url_ok = false if ln =~ /\.com\/projects\/Framework/
			if ln =~ /File\.open/ and ln =~ /[\"\'][arw]/
				if not ln =~ /[\"\'][wra]\+?b\+?[\"\']/
					warn("File.open without binary mode", idx)
				end
			end

			if ln =~/^[ \t]*load[ \t]+[\x22\x27]/
				error("Loading (not requiring) a file: #{ln.inspect}", idx)
			end

			# The rest of these only count if it's not a comment line
			next if ln =~ /[[:space:]]*#/

			if ln =~ /\$std(?:out|err)/i or ln =~ /[[:space:]]puts/
				no_stdio = false
				error("Writes to stdout", idx)
			end
		}
	end

	private

	def load_file(file)
		f = open(file, 'rb')
		buf = f.read(f.stat.size)
		f.close
		return buf
	end
end

def run_checks(f_rel)
	tidy = Msftidy.new(f_rel)
	tidy.check_ref_identifiers
	tidy.check_old_keywords
	tidy.check_verbose_option
	tidy.check_badchars
	tidy.check_extname
	tidy.test_old_rubies(f_rel)
	tidy.check_ranking
	tidy.check_disclosure_date
	tidy.check_title_casing
	tidy.check_bad_terms
	tidy.check_function_basics
	tidy.check_lines
end

##
#
# Main program
#
##

dirs = ARGV

if dirs.length < 1
	$stderr.puts "Usage: #{File.basename(__FILE__)} <directory or file>"
	exit(1)
end

dirs.each { |dir|
	f = nil
	old_dir = nil

	if dir
		if File.file?(dir)
			# whoa, a single file!
			f = File.basename(dir)
			dir = File.dirname(dir)
		end

		old_dir = Dir.getwd
		Dir.chdir(dir)
		dparts = dir.split('/')
	else
		dparts = []
	end

	# Only one file?
	if f
		run_checks(f)
	else
		# Do a recursive check of the specified directory
		Dir.glob('**/*.rb') { |f|
			run_checks(f)
		}
	end

	Dir.chdir(old_dir)
}
