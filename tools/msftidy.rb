#!/usr/bin/env ruby
# -*- coding: binary -*-
#
# Check (recursively) for style compliance violations and other
# tree inconsistencies.
#
# by jduck and friends
#
require 'fileutils'
require 'find'
require 'time'

CHECK_OLD_RUBIES = !!ENV['MSF_CHECK_OLD_RUBIES']
SPOTCHECK_RECENT = !!ENV['MSF_SPOTCHECK_RECENT']

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

  def green
    "\e[1;32;40m#{self}\e[0m"
  end

  def ascii_only?
    self =~ Regexp.new('[\x00-\x08\x0b\x0c\x0e-\x19\x7f-\xff]', nil, 'n') ? false : true
  end
end

class Msftidy

  LONG_LINE_LENGTH = 200 # From 100 to 200 which is stupidly long

  # Status codes
  OK       = 0x00
  WARNINGS = 0x10
  ERRORS   = 0x20

  attr_reader :full_filepath, :source, :stat, :name, :status

  def initialize(source_file)
    @full_filepath = source_file
    @source  = load_file(source_file)
    @status  = OK
    @name    = File.basename(source_file)
  end

  public

  #
  # Display a warning message, given some text and a number. Warnings
  # are usually style issues that may be okay for people who aren't core
  # Framework developers.
  #
  # @return status [Integer] Returns WARNINGS unless we already have an
  # error.
  def warn(txt, line=0) line_msg = (line>0) ? ":#{line}" : ''
    puts "#{@full_filepath}#{line_msg} - [#{'WARNING'.yellow}] #{txt}"
    @status == ERRORS ? @status = ERRORS : @status = WARNINGS
  end

  #
  # Display an error message, given some text and a number. Errors
  # can break things or are so egregiously bad, style-wise, that they
  # really ought to be fixed.
  #
  # @return status [Integer] Returns ERRORS
  def error(txt, line=0)
    line_msg = (line>0) ? ":#{line}" : ''
    puts "#{@full_filepath}#{line_msg} - [#{'ERROR'.red}] #{txt}"
    @status = ERRORS
  end

  # Currently unused, but some day msftidy will fix errors for you.
  def fixed(txt, line=0)
    line_msg = (line>0) ? ":#{line}" : ''
    puts "#{@full_filepath}#{line_msg} - [#{'FIXED'.green}] #{txt}"
  end


  ##
  #
  # The functions below are actually the ones checking the source code
  #
  ##

  def check_mode
    unless (@stat.mode & 0111).zero?
      warn("Module should not be marked executable")
    end
  end

  def check_shebang
    if @source.lines.first =~ /^#!/
      warn("Module should not have a #! line")
    end
  end

  def check_nokogiri
    msg = "Requiring Nokogiri in modules can be risky, use REXML instead."
    has_nokogiri = false
    @source.each_line do |line|
      if line =~ /^\s*(require|load)\s+['"]nokogiri['"]/
        has_nokogiri = true
        break
      end
    end
    error(msg) if has_nokogiri
  end

  def check_ref_identifiers
    in_super = false
    in_refs  = false

    @source.each_line do |line|
      if !in_super and line =~ /\s+super\(/
        in_super = true
      elsif in_super and line =~ /[[:space:]]*def \w+[\(\w+\)]*/
        in_super = false
        break
      end

      if in_super and line =~ /["']References["'][[:space:]]*=>/
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
        when 'ZDI'
          warn("Invalid ZDI reference") if value !~ /^\d{2}-\d{3}$/
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

  def check_snake_case_filename
    sep = File::SEPARATOR
    good_name = Regexp.new "^[a-z0-9_#{sep}]+\.rb$"
    unless @name =~ good_name
      warn "Filenames should be alphanum and snake case."
    end
  end

  def check_comment_splat
    if @source =~ /^# This file is part of the Metasploit Framework and may be subject to/
      warn("Module contains old license comment, use tools/dev/resplat.rb <filename>.")
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

    if @source =~ /["']Version["'][[:space:]]*=>[[:space:]]*['"]\$Revision\$['"]/
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
      if !in_super and line =~ /\s+super\(/
        in_super = true
      elsif in_super and line =~ /[[:space:]]*def \w+[\(\w+\)]*/
        in_super = false
        break
      end

      #
      # While in super() code block
      #
      if in_super and line =~ /["']Name["'][[:space:]]*=>[[:space:]]*['|"](.+)['|"]/
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
      if in_super and !in_author and line =~ /["']Author["'][[:space:]]*=>/
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

  def test_old_rubies
    return true unless CHECK_OLD_RUBIES
    return true unless Object.const_defined? :RVM
    puts "Checking syntax for #{@name}."
    rubies ||= RVM.list_strings
    res = %x{rvm all do ruby -c #{@full_filepath}}.split("\n").select {|msg| msg =~ /Syntax OK/}
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
    if @source =~ /["']DisclosureDate["'].*\=\>[\x0d\x20]*['\"](.+)['\"]/
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
    whitelist = %w{
      a an and as at avserve callmenum configdir connect debug docbase
      dtspcd execve file for from getinfo goaway gsad hetro historysearch
      htpasswd id in inetd iseemedia jhot libxslt lmgrd lnk load main map
      migrate mimencode multisort name net netcat nodeid ntpd nttrans of
      on onreadystatechange or ovutil path pbot pfilez pgpass pingstr pls
      popsubfolders prescan readvar relfile rev rexec rlogin rsh rsyslog sa
      sadmind say sblistpack spamd sreplace tagprinter the to twikidraw udev
      uplay user username via welcome with ypupdated zsudo
    }

    if @source =~ /["']Name["'][[:space:]]*=>[[:space:]]*['"](.+)['"],*$/
      words = $1.split
      words.each do |word|
        if whitelist.include?(word)
          next
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
        warn("Line exceeding #{LONG_LINE_LENGTH} bytes", idx)
      end

      if ln =~ /[ \t]$/
        warn("Spaces at EOL", idx)
      end

      # Check for mixed tab/spaces. Upgrade this to an error() soon.
      if (ln.length > 1) and (ln =~ /^([\t ]*)/) and ($1.match(/\x20\x09|\x09\x20/))
        warn("Space-Tab mixed indent: #{ln.inspect}", idx)
      end

      # Check for tabs. Upgrade this to an error() soon.
      if (ln.length > 1) and (ln =~ /^\x09/)
        warn("Tabbed indent: #{ln.inspect}", idx)
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
        next if ln =~ /^[\s]*["][^"]+\$std(?:out|err)/
        no_stdio = false
        error("Writes to stdout", idx)
      end

      # do not change datastore in code
      if ln =~ /(?<!\.)datastore\[["'][^"']+["']\]\s*=(?![=~>])/
        error("datastore is modified in code: #{ln.inspect}", idx)
      end
    }
  end

  def check_vuln_codes
    checkcode = @source.scan(/(Exploit::)?CheckCode::(\w+)/).flatten[1]
    if checkcode and checkcode !~ /^Unknown|Safe|Detected|Appears|Vulnerable|Unsupported$/
      error("Unrecognized checkcode: #{checkcode}")
    end
  end

  private

  def load_file(file)
    f = open(file, 'rb')
    @stat = f.stat
    buf = f.read(@stat.size)
    f.close
    return buf
  end
end

#
# Run all the msftidy checks.
#
# @param full_filepath [String] The full file path to check
# @return status [Integer] A status code suitable for use as an exit status
def run_checks(full_filepath)
  tidy = Msftidy.new(full_filepath)
  tidy.check_mode
  tidy.check_shebang
  tidy.check_nokogiri
  tidy.check_ref_identifiers
  tidy.check_old_keywords
  tidy.check_verbose_option
  tidy.check_badchars
  tidy.check_extname
  tidy.test_old_rubies
  tidy.check_ranking
  tidy.check_disclosure_date
  tidy.check_title_casing
  tidy.check_bad_terms
  tidy.check_function_basics
  tidy.check_lines
  tidy.check_snake_case_filename
  tidy.check_comment_splat
  tidy.check_vuln_codes
  return tidy
end

##
#
# Main program
#
##

dirs = ARGV

if SPOTCHECK_RECENT
  msfbase = %x{\\git rev-parse --show-toplevel}.strip
  if File.directory? msfbase
    Dir.chdir(msfbase)
  else
    $stderr.puts "You need a git binary in your path to use this functionality."
    exit(0x02)
  end
  last_release = %x{\\git tag -l #{DateTime.now.year}\\*}.split.last
  new_modules = %x{\\git diff #{last_release}..HEAD --name-only --diff-filter A modules}
  dirs = dirs | new_modules.split
end

# Don't print an error if there's really nothing to check.
unless SPOTCHECK_RECENT
  if dirs.length < 1
    $stderr.puts "Usage: #{File.basename(__FILE__)} <directory or file>"
    exit(0x01)
  end
end

dirs.each do |dir|
  begin
    Find.find(dir) do |full_filepath|
      next if full_filepath =~ /\.git[\x5c\x2f]/
      next unless File.file? full_filepath
      next unless full_filepath =~ /\.rb$/
      msftidy = run_checks(full_filepath)
      @exit_status = msftidy.status if (msftidy.status > @exit_status.to_i)
    end
  rescue Errno::ENOENT
    $stderr.puts "#{File.basename(__FILE__)}: #{dir}: No such file or directory"
  end
end

exit(@exit_status.to_i)
