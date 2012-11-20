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
	# The following two functions only print what you throw at them.
	# With an option of displaying the line number.
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
		rubies.size == res.size

		error("Fails alternate Ruby version check") if rubies.size
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
		if @source =~ /'DisclosureDate'.*\=\>[\x0d|\x20]*['|\"](.+)['|\"]/
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

	def check_title_format
		if @source =~ /'Name'\s+=>\s[\x22\x27](.+)[\x22\x27],\s*$/
			name = $1
			words = $1.split
			[words.first, words.last].each do |word|
				if word[0,1] =~ /[a-z]/ and word[1,1] !~ /[A-Z0-9]/
					next if word =~ /php[A-Z]/
					next if %w{iseemedia activePDF freeFTPd osCommerce myBB qdPM}.include? word
					warn("Improper capitalization in module title: '#{word}...'")
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
	tidy.check_extname
	tidy.test_old_rubies(f_rel)
	tidy.check_ranking
	tidy.check_disclosure_date
	tidy.check_title_format
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
