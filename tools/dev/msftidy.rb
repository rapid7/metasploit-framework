#!/usr/bin/env ruby
# -*- coding: binary -*-

#
# Check (recursively) for style compliance violations and other
# tree inconsistencies.
#
# by jduck, todb, and friends
#

require 'fileutils'
require 'find'
require 'time'

CHECK_OLD_RUBIES = !!ENV['MSF_CHECK_OLD_RUBIES']
SUPPRESS_INFO_MESSAGES = !!ENV['MSF_SUPPRESS_INFO_MESSAGES']

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

  def cyan
    "\e[1;36;40m#{self}\e[0m"
  end
end

class Msftidy

  # Status codes
  OK       = 0
  WARNING  = 1
  ERROR    = 2

  # Some compiles regexes
  REGEX_MSF_EXPLOIT = / \< Msf::Exploit/
  REGEX_IS_BLANK_OR_END = /^\s*end\s*$/

  attr_reader :full_filepath, :source, :stat, :name, :status

  def initialize(source_file)
    @full_filepath = source_file
    @module_type = File.dirname(File.expand_path(@full_filepath))[/\/modules\/([^\/]+)/, 1]
    @source  = load_file(source_file)
    @lines   = @source.lines # returns an enumerator
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
    puts "#{@full_filepath}#{line_msg} - [#{'WARNING'.yellow}] #{cleanup_text(txt)}"
    @status = WARNING if @status < WARNING
  end

  #
  # Display an error message, given some text and a number. Errors
  # can break things or are so egregiously bad, style-wise, that they
  # really ought to be fixed.
  #
  # @return status [Integer] Returns ERRORS
  def error(txt, line=0)
    line_msg = (line>0) ? ":#{line}" : ''
    puts "#{@full_filepath}#{line_msg} - [#{'ERROR'.red}] #{cleanup_text(txt)}"
    @status = ERROR if @status < ERROR
  end

  # Currently unused, but some day msftidy will fix errors for you.
  def fixed(txt, line=0)
    line_msg = (line>0) ? ":#{line}" : ''
    puts "#{@full_filepath}#{line_msg} - [#{'FIXED'.green}] #{cleanup_text(txt)}"
  end

  #
  # Display an info message. Info messages do not alter the exit status.
  #
  def info(txt, line=0)
    return if SUPPRESS_INFO_MESSAGES
    line_msg = (line>0) ? ":#{line}" : ''
    puts "#{@full_filepath}#{line_msg} - [#{'INFO'.cyan}] #{cleanup_text(txt)}"
  end

  ##
  #
  # The functions below are actually the ones checking the source code
  #
  ##

  def check_shebang
    if @lines.first =~ /^#!/
      warn("Module should not have a #! line")
    end
  end

  # Updated this check to see if Nokogiri::XML.parse is being called
  # specifically. The main reason for this concern is that some versions
  # of libxml2 are still vulnerable to XXE attacks. REXML is safer (and
  # slower) since it's pure ruby. Unfortunately, there is no pure Ruby
  # HTML parser (except Hpricot which is abandonware) -- easy checks
  # can avoid Nokogiri (most modules use regex anyway), but more complex
  # checks tends to require Nokogiri for HTML element and value parsing.
  def check_nokogiri
    msg = "Using Nokogiri in modules can be risky, use REXML instead."
    has_nokogiri = false
    has_nokogiri_xml_parser = false
    @lines.each do |line|
      if has_nokogiri
        if line =~ /Nokogiri::XML\.parse/ or line =~ /Nokogiri::XML::Reader/
          has_nokogiri_xml_parser = true
          break
        end
      else
        has_nokogiri = line_has_require?(line, 'nokogiri')
      end
    end
    error(msg) if has_nokogiri_xml_parser
  end

  def check_ref_identifiers
    in_super     = false
    in_refs      = false
    in_notes     = false
    cve_assigned = false

    @lines.each do |line|
      if !in_super and line =~ /\s+super\(/
        in_super = true
      elsif in_super and line =~ /[[:space:]]*def \w+[\(\w+\)]*/
        in_super = false
        break
      end

      if in_super and line =~ /["']References["'][[:space:]]*=>/
        in_refs = true
      elsif in_super and in_refs and line =~ /^[[:space:]]+\],*/m
        in_refs = false
      elsif in_super and line =~ /["']Notes["'][[:space:]]*=>/
        in_notes = true
      elsif in_super and in_notes and line =~ /^[[:space:]]+\},*/m
        break
      elsif in_super and in_refs and line =~ /[^#]+\[[[:space:]]*['"](.+)['"][[:space:]]*,[[:space:]]*['"](.+)['"][[:space:]]*\]/
        identifier = $1.strip.upcase
        value      = $2.strip

        case identifier
        when 'CVE'
          cve_assigned = true
          warn("Invalid CVE format: '#{value}'") if value !~ /^\d{4}\-\d{4,}$/
        when 'BID'
          warn("Invalid BID format: '#{value}'") if value !~ /^\d+$/
        when 'MSB'
          warn("Invalid MSB format: '#{value}'") if value !~ /^MS\d+\-\d+$/
        when 'MIL'
          warn("milw0rm references are no longer supported.")
        when 'EDB'
          warn("Invalid EDB reference") if value !~ /^\d+$/
        when 'US-CERT-VU'
          warn("Invalid US-CERT-VU reference") if value !~ /^\d+$/
        when 'ZDI'
          warn("Invalid ZDI reference") if value !~ /^\d{2}-\d{3}$/
        when 'WPVDB'
          warn("Invalid WPVDB reference") if value !~ /^\d+$/
        when 'PACKETSTORM'
          warn("Invalid PACKETSTORM reference") if value !~ /^\d+$/
        when 'URL'
          if value =~ /^https?:\/\/cvedetails\.com\/cve/
            warn("Please use 'CVE' for '#{value}'")
          elsif value =~ /^https?:\/\/www\.securityfocus\.com\/bid\//
            warn("Please use 'BID' for '#{value}'")
          elsif value =~ /^https?:\/\/www\.microsoft\.com\/technet\/security\/bulletin\//
            warn("Please use 'MSB' for '#{value}'")
          elsif value =~ /^https?:\/\/www\.exploit\-db\.com\/exploits\//
            warn("Please use 'EDB' for '#{value}'")
          elsif value =~ /^https?:\/\/www\.kb\.cert\.org\/vuls\/id\//
            warn("Please use 'US-CERT-VU' for '#{value}'")
          elsif value =~ /^https?:\/\/wpvulndb\.com\/vulnerabilities\//
            warn("Please use 'WPVDB' for '#{value}'")
          elsif value =~ /^https?:\/\/(?:[^\.]+\.)?packetstormsecurity\.(?:com|net|org)\//
            warn("Please use 'PACKETSTORM' for '#{value}'")
          end
        when 'AKA'
          warn("Please include AKA values in the 'notes' section, rather than in 'references'.")
        end
      end

      # If a NOCVE reason was provided in notes, ignore the fact that the references might lack a CVE
      if in_super and in_notes and line =~ /^[[:space:]]+["']NOCVE["'][[:space:]]+=>[[:space:]]+\[*["'](.+)["']\]*/
        cve_assigned = true
      end
    end

    # This helps us track when CVEs aren't assigned
    unless cve_assigned
      info('No CVE references found. Please check before you land!')
    end
  end

  def check_self_class
    in_register = false
    @lines.each do |line|
      (in_register = true) if line =~ /^\s*register_(?:advanced_)?options/
      (in_register = false) if line =~ /^\s*end/
      if in_register && line =~ /\],\s*self\.class\s*\)/
        warn('Explicitly using self.class in register_* is not necessary')
        break
      end
    end
  end

  # See if 'require "rubygems"' or equivalent is used, and
  # warn if so. Since Ruby 1.9 this has not been necessary and
  # the framework only suports 1.9+
  def check_rubygems
    @lines.each do |line|
      if line_has_require?(line, 'rubygems')
        warn("Explicitly requiring/loading rubygems is not necessary")
        break
      end
    end
  end

  def check_msf_core
    @lines.each do |line|
      if line_has_require?(line, 'msf/core')
        warn('Explicitly requiring/loading msf/core is not necessary')
        break
      end
    end
  end

  # Does the given line contain a require/load of the specified library?
  def line_has_require?(line, lib)
    line =~ /^\s*(require|load)\s+['"]#{lib}['"]/
  end

  # This check also enforces namespace module name reversibility
  def check_snake_case_filename
    if @name !~ /^[a-z0-9]+(?:_[a-z0-9]+)*\.rb$/
      warn('Filenames must be lowercase alphanumeric snake case.')
    end
  end

  def check_comment_splat
    if @source =~ /^# This file is part of the Metasploit Framework and may be subject to/
      warn("Module contains old license comment.")
    end
    if @source =~ /^# This module requires Metasploit: http:/
      warn("Module license comment link does not use https:// URL scheme.")
      fixed('# This module requires Metasploit: https://metasploit.com/download', 1)
    end
  end

  def check_old_keywords
    max_count = 10
    counter   = 0
    if @source =~ /^##/
      @lines.each do |line|
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

    @lines.each do |line|
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

        # Since we're looking at the module title, this line clearly cannot be
        # the author block, so no point to run more code below.
        next
      end

      # XXX: note that this is all very fragile and regularly incorrectly parses
      # the author
      #
      # Mark our 'Author' block
      #
      if in_super and !in_author and line =~ /["']Author["'][[:space:]]*=>/
        in_author = true
      elsif in_super and in_author and line =~ /\],*\n/ or line =~ /['"][[:print:]]*['"][[:space:]]*=>/
        in_author = false
      end


      #
      # While in 'Author' block, check for malformed authors
      #
      if in_super and in_author
        if line =~ /Author['"]\s*=>\s*['"](.*)['"],/
          author_name = Regexp.last_match(1)
        elsif line =~ /Author/
          author_name = line.scan(/\[[[:space:]]*['"](.+)['"]/).flatten[-1] || ''
        else
          author_name = line.scan(/['"](.+)['"]/).flatten[-1] || ''
        end

        if author_name =~ /^@.+$/
          error("No Twitter handles, please. Try leaving it in a comment instead.")
        end

        unless author_name.empty?
          author_open_brackets = author_name.scan('<').size
          author_close_brackets = author_name.scan('>').size
          if author_open_brackets != author_close_brackets
            error("Author has unbalanced brackets: #{author_name}")
          end
        end
      end
    end
  end

  def check_extname
    if File.extname(@name) != '.rb'
      error("Module should be a '.rb' file, or it won't load.")
    end
  end

  def check_old_rubies
    return true unless CHECK_OLD_RUBIES
    return true unless Object.const_defined? :RVM
    puts "Checking syntax for #{@name}."
    rubies ||= RVM.list_strings
    res = %x{rvm all do ruby -c #{@full_filepath}}.split("\n").select {|msg| msg =~ /Syntax OK/}
    error("Fails alternate Ruby version check") if rubies.size != res.size
  end

  def is_exploit_module?
    ret = false
    if @source =~ REGEX_MSF_EXPLOIT
      # having Msf::Exploit is good indicator, but will false positive on
      # specs and other files containing the string, but not really acting
      # as exploit modules, so here we check the file for some actual contents
      # this could be done in a simpler way, but this let's us add more later
      msf_exploit_line_no = nil
      @lines.each_with_index do |line, idx|
        if line =~ REGEX_MSF_EXPLOIT
          # note the line number
          msf_exploit_line_no = idx
        elsif msf_exploit_line_no
          # check there is anything but empty space between here and the next end
          # something more complex could be added here
          if line !~ REGEX_IS_BLANK_OR_END
            # if the line is not 'end' and is not blank, prolly exploit module
            ret = true
            break
          else
            # then keep checking in case there are more than one Msf::Exploit
            msf_exploit_line_no = nil
          end
        end
      end
    end
    ret
  end

  def check_ranking
    return unless is_exploit_module?

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
    elsif @source =~ /['"](SideEffects|Stability|Reliability)['"]\s*=/
      info('No Rank, however SideEffects, Stability, or Reliability are provided')
    else
      warn('No Rank specified. The default is NormalRanking. Please add an explicit Rank value.')
    end
  end

  def check_disclosure_date
    return if @source =~ /Generic Payload Handler/

    # Check disclosure date format
    if @source =~ /["']DisclosureDate["'].*\=\>[\x0d\x20]*['\"](.+?)['\"]/
      d = $1  #Captured date
      # Flag if overall format is wrong
      if d =~ /^... (?:\d{1,2},? )?\d{4}$/
        # Flag if month format is wrong
        m = d.split[0]
        months = [
          'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
          'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'
        ]

        error('Incorrect disclosure month format') if months.index(m).nil?
      # XXX: yyyy-mm is interpreted as yyyy-01-mm by Date::iso8601
      elsif d =~ /^\d{4}-\d{2}-\d{2}$/
        begin
          Date.iso8601(d)
        rescue ArgumentError
          error('Incorrect ISO 8601 disclosure date format')
        end
      else
        error('Incorrect disclosure date format')
      end
    else
      error('Exploit is missing a disclosure date') if is_exploit_module?
    end
  end

  def check_bad_terms
    # "Stack overflow" vs "Stack buffer overflow" - See explanation:
    # http://blogs.technet.com/b/srd/archive/2009/01/28/stack-overflow-stack-exhaustion-not-the-same-as-stack-buffer-overflow.aspx
    if @module_type == 'exploit' && @source.gsub("\n", "") =~ /stack[[:space:]]+overflow/i
      warn('Contains "stack overflow" You mean "stack buffer overflow"?')
    elsif @module_type == 'auxiliary' && @source.gsub("\n", "") =~ /stack[[:space:]]+overflow/i
      warn('Contains "stack overflow" You mean "stack exhaustion"?')
    end
  end

  def check_bad_super_class
    # skip payloads, as they don't have a super class
    return if @module_type == 'payloads'

    # get the super class in an ugly way
    unless (super_class = @source.scan(/class Metasploit(?:\d|Module)\s+<\s+(\S+)/).flatten.first)
      error('Unable to determine super class')
      return
    end

    prefix_super_map = {
      'evasion' => /^Msf::Evasion$/,
      'auxiliary' => /^Msf::Auxiliary$/,
      'exploits' => /^Msf::Exploit(?:::Local|::Remote)?$/,
      'encoders' => /^(?:Msf|Rex)::Encoder/,
      'nops' => /^Msf::Nop$/,
      'post' => /^Msf::Post$/
    }

    if prefix_super_map.key?(@module_type)
      unless super_class =~ prefix_super_map[@module_type]
        error("Invalid super class for #{@module_type} module (found '#{super_class}', expected something like #{prefix_super_map[@module_type]}")
      end
    else
      warn("Unexpected and potentially incorrect super class found ('#{super_class}')")
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

  def check_bad_class_name
    if @source =~ /^\s*class (Metasploit\d+)\s*</
      warn("Please use 'MetasploitModule' as the class name (you used #{Regexp.last_match(1)})")
    end
  end

  def check_lines
    url_ok     = true
    no_stdio   = true
    in_comment = false
    in_literal = false
    src_ended  = false
    idx        = 0

    @lines.each do |ln|
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
      next if ln =~ /^[[:space:]]*#/

      if ln =~ /\$std(?:out|err)/i or ln =~ /[[:space:]]puts/
        next if ln =~ /["'][^"']*\$std(?:out|err)[^"']*["']/
        no_stdio = false
        error("Writes to stdout", idx)
      end

      # do not read Set-Cookie header (ignore commented lines)
      if ln =~ /^(?!\s*#).+\[['"]Set-Cookie['"]\](?!\s*=[^=~]+)/i
        warn("Do not read Set-Cookie header directly, use res.get_cookies instead: #{ln}", idx)
      end

      # Auxiliary modules do not have a rank attribute
      if ln =~ /^\s*Rank\s*=\s*/ && @module_type == 'auxiliary'
        warn("Auxiliary modules have no 'Rank': #{ln}", idx)
      end

      if ln =~ /^\s*def\s+(?:[^\(\)#]*[A-Z]+[^\(\)]*)(?:\(.*\))?$/
        warn("Please use snake case on method names: #{ln}", idx)
      end

      if ln =~ /^\s*fail_with\(/
        unless ln =~ /^\s*fail_with\(.*Failure\:\:(?:None|Unknown|Unreachable|BadConfig|Disconnected|NotFound|UnexpectedReply|TimeoutExpired|UserInterrupt|NoAccess|NoTarget|NotVulnerable|PayloadFailed),/
          error("fail_with requires a valid Failure:: reason as first parameter: #{ln}", idx)
        end
      end

      if ln =~ /['"]ExitFunction['"]\s*=>/
        warn("Please use EXITFUNC instead of ExitFunction #{ln}", idx)
        fixed(line.gsub('ExitFunction', 'EXITFUNC'), idx)
      end

      # Output from Base64.encode64 method contains '\n' new lines
      # for line wrapping and string termination
      if ln =~ /Base64\.encode64/
        info("Please use Base64.strict_encode64 instead of Base64.encode64")
      end
    end
  end

  def check_vuln_codes
    checkcode = @source.scan(/(Exploit::)?CheckCode::(\w+)/).flatten[1]
    if checkcode and checkcode !~ /^Unknown|Safe|Detected|Appears|Vulnerable|Unsupported$/
      error("Unrecognized checkcode: #{checkcode}")
    end
  end

  def check_vars_get
    test = @source.scan(/send_request_cgi\s*\(?\s*\{?\s*['"]uri['"]\s*=>\s*[^=})]*?\?[^,})]+/im)
    unless test.empty?
      test.each { |item|
        warn("Please use vars_get in send_request_cgi: #{item}")
      }
    end
  end

  def check_newline_eof
    if @source !~ /(?:\r\n|\n)\z/m
      warn('Please add a newline at the end of the file')
    end
  end

  def check_udp_sock_get
    if @source =~ /udp_sock\.get/m && @source !~ /udp_sock\.get\([a-zA-Z0-9]+/
      warn('Please specify a timeout to udp_sock.get')
    end
  end

  # At one point in time, somebody committed a module with a bad metasploit.com URL
  # in the header -- http//metasploit.com/download rather than https://metasploit.com/download.
  # This module then got copied and committed 20+ times and is used in numerous other places.
  # This ensures that this stops.
  def check_invalid_url_scheme
    test = @source.scan(/^#.+https?\/\/(?:www\.)?metasploit.com/)
    unless test.empty?
      test.each { |item|
        warn("Invalid URL: #{item}")
      }
    end
  end

  # Check for (v)print_debug usage, since it doesn't exist anymore
  #
  # @see https://github.com/rapid7/metasploit-framework/issues/3816
  def check_print_debug
    if @source =~ /print_debug/
      error('Please don\'t use (v)print_debug, use vprint_(status|good|error|warning) instead')
    end
  end

  # Check for modules registering the DEBUG datastore option
  #
  # @see https://github.com/rapid7/metasploit-framework/issues/3816
  def check_register_datastore_debug
    if @source =~ /Opt.*\.new\(["'](?i)DEBUG(?-i)["']/
      error('Please don\'t register a DEBUG datastore option, it has an special meaning and is used for development')
    end
  end

  # Check for modules using the DEBUG datastore option
  #
  # @see https://github.com/rapid7/metasploit-framework/issues/3816
  def check_use_datastore_debug
    if @source =~ /datastore\[["'](?i)DEBUG(?-i)["']\]/
      error('Please don\'t use the DEBUG datastore option in production, it has an special meaning and is used for development')
    end
  end

  # Check for modules using the deprecated architectures
  #
  # @see https://github.com/rapid7/metasploit-framework/pull/7507
  def check_arch
    if @source =~ /ARCH_X86_64/
      error('Please don\'t use the ARCH_X86_64 architecture, use ARCH_X64 instead')
    end
  end

  # Check for modules having an Author section to ensure attribution
  #
  def check_author
    # Only the three common module types have a consistently defined info hash
    return unless %w[exploit auxiliary post].include?(@module_type)

    unless @source =~ /["']Author["'][[:space:]]*=>/
      error('Missing "Author" info, please add')
    end
  end

  #
  # Run all the msftidy checks.
  #
  def run_checks
    check_shebang
    check_nokogiri
    check_rubygems
    check_msf_core
    check_ref_identifiers
    check_self_class
    check_old_keywords
    check_verbose_option
    check_badchars
    check_extname
    check_old_rubies
    check_ranking
    check_disclosure_date
    check_bad_terms
    check_bad_super_class
    check_bad_class_name
    check_function_basics
    check_lines
    check_snake_case_filename
    check_comment_splat
    check_vuln_codes
    check_vars_get
    check_newline_eof
    check_udp_sock_get
    check_invalid_url_scheme
    check_print_debug
    check_register_datastore_debug
    check_use_datastore_debug
    check_arch
    check_author
  end

  private

  def load_file(file)
    f = open(file, 'rb')
    @stat = f.stat
    buf = f.read(@stat.size)
    f.close
    return buf
  end

  def cleanup_text(txt)
    # remove line breaks
    txt = txt.gsub(/[\r\n]/, ' ')
    # replace multiple spaces by one space
    txt.gsub(/\s{2,}/, ' ')
  end
end

##
#
# Main program
#
##

if __FILE__ == $PROGRAM_NAME
  dirs = ARGV

  @exit_status = 0

  if dirs.length < 1
    $stderr.puts "Usage: #{File.basename(__FILE__)} <directory or file>"
    @exit_status = 1
    exit(@exit_status)
  end

  dirs.each do |dir|
    begin
      Find.find(dir) do |full_filepath|
        next if full_filepath =~ /\.git[\x5c\x2f]/
        next unless File.file? full_filepath
        next unless File.extname(full_filepath) == '.rb'
        msftidy = Msftidy.new(full_filepath)
        # Executable files are now assumed to be external modules
        # but also check for some content to be sure
        next if File.executable?(full_filepath) && msftidy.source =~ /require ["']metasploit["']/
        msftidy.run_checks
        @exit_status = msftidy.status if (msftidy.status > @exit_status.to_i)
      end
    rescue Errno::ENOENT
      $stderr.puts "#{File.basename(__FILE__)}: #{dir}: No such file or directory"
    end
  end

  exit(@exit_status.to_i)
end
