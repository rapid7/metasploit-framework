#!/usr/bin/env ruby
#
# Check (recursively) for style compliance violations and other
# tree inconsistencies.
#
# by jduck and friends
#

##
#
# Supporting sub-routines
#
##

LONG_LINE_LENGTH = 200 # From 100 to 200 which is stupidly long
CHECK_OLD_RUBIES = !!ENV['MSF_CHECK_OLD_RUBIES']

if CHECK_OLD_RUBIES
	require 'rvm'
	warn "This is going to take a while, depending on the number of Rubies you have installed."
end

def show_count(f, txt, num)
	puts "%s ... %s: %u" % [f, txt, num] if num > 0
end

def show_missing(f, txt, val)
	puts '%s ... %s' % [f, txt] if not val
end

# This check is only enabled if the environment variable MSF_CHECK_OLD_RUBIES is set
def test_old_rubies(f_rel)
	return true unless CHECK_OLD_RUBIES
	return true unless Object.const_defined? :RVM
	puts "Checking syntax for #{f_rel}."
	@rubies ||= RVM.list_strings
	res = %x{rvm all do ruby -c #{f_rel}}.split("\n").select {|msg| msg =~ /Syntax OK/}
	@rubies.size == res.size
end


def check_single_file(dparts, fparts, f_rel)
	f = (dparts + fparts).join('/')
	# puts "Checking: #{f.inspect}"

	# Put some kind of blacklist mechanism here, yaml config would be nice...

	# check for executable
	f_exec = File.executable?(f_rel)
	show_missing(f, "WARNING: is executable", !f_exec)

	# check all installed rubies
	
	old_rubies = test_old_rubies(f_rel)
	show_missing(f, "ERROR: fails alternate Ruby version check", old_rubies)


	# check various properties based on content
	content = File.open(f_rel, "rb").read

	# check criteria based on whole content
	if content =~ / \< Msf::Exploit/
		has_rank = false
		has_dd = false

		has_rank = true if content =~ /Rank =/
		has_dd = true if content =~ /DisclosureDate/ or content =~ /Generic Payload Handler/

		show_missing(f, 'ERROR: missing exploit ranking', has_rank)
		show_missing(f, 'ERROR: missing disclosure date', has_dd)
	end

	# Check disclosure date format
	if content =~ /'DisclosureDate' => ['|\"](.+)['|\"]/
		d = $1  #Captured date
		# Flag if overall format is wrong
		if d =~ /^... \d{1,2} \d{4}/
			# Flag if month format is wrong
			m = d.split[0]
			months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
			if months.index(m).nil?
				show_missing(f, 'WARNING: incorrect disclosure month format', false)
			end
		else
			show_missing(f, 'WARNING: incorrect disclosure date format', false)
		end
	end

	# Check title format
	if content =~ /'Name'\s+=>\s[\x22\x27](.+)[\x22\x27],\s*$/
		name = $1
		words = $1.split
		[words.first, words.last].each do |word|
			if word[0,1] =~ /[a-z]/ and word[1,1] !~ /[A-Z0-9]/
				next if word =~ /php[A-Z]/
				next if %w{iseemedia activePDF freeFTPd osCommerce myBB}.include? word
				show_missing(f, "WARNING: bad capitalization in module title: #{word}", false)
			end
		end
	end

	# If an exploit module mentinos the word "stack overflow", chances are they mean "stack buffer overflow".
	# "stack overflow" means "stack exhaustion".  See explanation:
	# http://blogs.technet.com/b/srd/archive/2009/01/28/stack-overflow-stack-exhaustion-not-the-same-as-stack-buffer-overflow.aspx
	bad_term = true
	if content =~ /class Metasploit\d < Msf::Exploit::Remote/ and content.gsub("\n", "") =~ /stack[[:space:]]+overflow/i
		bad_term = false
		show_missing(f, 'WARNING: contains "stack overflow" You mean "stack buffer overflow"?', bad_term)
	elsif content =~ /class Metasploit\d < Msf::Auxiliary/ and content.gsub("\n", "") =~ /stack[[:space:]]+overflow/i
		bad_term = false
		show_missing(f, 'WARNING: contains "stack overflow" You mean "stack exhaustion"?', bad_term)
	end

	# Check function naming style and arg length
	functions = content.scan(/def (\w+)\(*(.+)\)*/)

	functions.each do |func_name, args|
=begin
		# Check Ruby variable naming style
		if func_name =~ /[a-z][A-Z]/ or func_name =~ /[A-Z][a-z]/
			show_missing(f, "WARNING: Poor function naming style for: '#{func_name}'", false)
		end
=end

		# Check argument length
		args_length = args.split(",").length
		if args_length > 6
			show_missing(f, "WARNING: Poorly designed argument list in '#{func_name}'. Try a hash.", false)
		end
	end

=begin
	vars = content.scan(/([\x20|\w]+) \= [\'|\"]*\w[\'|\"]*/).flatten
	vars.each do |v|
		v = v.strip
		next if v =~ /^var/ or v =~ /^Rank/
		if v =~ /[a-z][A-Z]/ or v =~ /[A-Z][a-z]/
			show_missing(f, "WARNING: Poor variable naming style for: '#{v}'", false)
		end
	end
=end

	# check criteria based on individual lines
	spaces = 0
	bi = []
	ll = []
	bc = []
	cr = 0
	url_ok = true
	nbo = 0 # non-bin open
	long_lines = 0
	no_stdio = true

	in_comment = false
	in_literal = false
	src_ended = false

	idx = 0
	content.each_line { |ln|
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
			bc << [ idx, ln.inspect]
		end

		if (ln.length > LONG_LINE_LENGTH)
			ll << [ idx, ln ]
		end

		spaces += 1 if ln =~ /[ \t]$/
		if (ln.length > 1) and (ln =~ /^([\t ]*)/) and ($1.include?(' '))
			bi << [ idx, ln ]
		end
		cr += 1 if ln =~ /\r$/
		url_ok = false if ln =~ /\.com\/projects\/Framework/
		if ln =~ /File\.open/ and ln =~ /[\"\'][arw]/
			if not ln =~ /[\"\'][wra]\+?b\+?[\"\']/
				nbo += 1
			end
		end

		# The rest of these only count if it's not a comment line
		next if ln =~ /[[:space:]]*#/

		if ln =~ /\$std(?:out|err)/ or ln =~ /[[:space:]]puts/
			no_stdio = false
		end
	}

	# report information for this file
	show_count(f, 'WARNING: spaces at EOL', spaces)
	if bi.length > 0
		puts '%s ... bad indent: %u' % [f, bi.length]
		bi.each { |el|
			el[1] = el[1].inspect
			puts '  %8d: %s' % el
		}
	end

	if ll.length > 0
		puts "WARNING: %s ... lines longer than #{LONG_LINE_LENGTH} columns: %u" % [f, ll.length]
		ll.each { |el|
			el[1] = el[1].inspect
			puts '  %8d: %s' % el
		}
	end

	if bc.length > 0
		puts "ERROR: %s ... probably has unicode: %u" % [f, bc.length]
		bc.each { |ec|
			ec[1] = ec[1].inspect
			puts '  %8d: %s' % ec
		}
	end

	show_count(f, 'WARNING: carriage return EOL', cr)
	show_missing(f, 'WARNING: incorrect URL to framework site', url_ok)
	show_missing(f, 'ERROR: writes to stdout', no_stdio)
	show_count(f, 'WARNING: File.open without binary mode', nbo)
end



##
#
# Main program
#
##

dirs = ARGV

if dirs.length < 1
	$stderr.puts "usage: #{File.basename(__FILE__)} <directory or file>"
	exit(1)
end

dirs.each { |dir|
	# process all args

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
		check_single_file(dparts, [ f ], f)
	else
		# Do a recursive check of the specified directory
		Dir.glob('**/*.rb') { |f|
			check_single_file(dparts, f.split('/'), f)
		}
	end

	Dir.chdir(old_dir)
}
