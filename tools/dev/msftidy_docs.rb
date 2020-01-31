#!/usr/bin/env ruby
# -*- coding: binary -*-

#
# Check (recursively) for style compliance violations and other
# tree inconsistencies.
#
# by h00die
#

require 'fileutils'
require 'find'
require 'time'

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

class MsftidyDoc

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

  def has_module
    module_filepath = @full_filepath.sub('documentation/','').sub('/exploit/', '/exploits/')
    found = false
    ['.rb', '.py', '.go'].each do |ext|
      if File.file? module_filepath.sub(/.md$/, ext)
        found = true
        break
      end
    end
    unless found
      error("Doc missing module.  Check file name and path(s) are correct. Doc: #{@full_filepath}")
    end
  end

  def check_start_with_vuln_app
    unless @lines.first =~ /^## Vulnerable Application$/
      warn('Docs should start with ## Vulnerable Application')
    end 
  end

  def has_h2_headings
    has_vulnerable_application = false
    has_verification_steps = false
    has_scenarios = false
    has_options = false
    has_bad_description = false
    has_bad_intro = false

    @lines.each do |line|
      if line =~ /^## Vulnerable Application$/
        has_vulnerable_application = true
        next
      end

      if line =~ /^## Verification Steps$/
        has_verification_steps = true
        next
      end

      if line =~ /^## Scenarios$/
        has_scenarios = true
        next
      end

      if line =~ /^## Options$/
        has_options = true
        next
      end

      if line =~ /^## Description$/
        has_bad_description = true
        next
      end

      if line =~ /^## (Intro|Introduction)$/
        has_bad_intro = true
        next
      end
    end

    unless has_vulnerable_application
      warn('Missing Section: ## Vulnerable Application')
    end

    unless has_verification_steps
      warn('Missing Section: ## Verification Steps')
    end

    unless has_scenarios
      warn('Missing Section: ## Scenarios')
    end

    unless has_options
      warn('Missing Section: ## Options')
    end

    if has_bad_description
      warn('Descriptions should be within Vulnerable Application, or an H3 sub-section of Vulnerable Application')
    end

    if has_bad_intro
      warn('Intro/Introduction should be within Vulnerable Application, or an H3 sub-section of Vulnerable Application')
    end
  end

  def check_newline_eof
    if @source !~ /(?:\r\n|\n)\z/m
      warn('Please add a newline at the end of the file')
    end
  end

  # This checks that the H2 headings are in teh right order.
  def h2_order
    unless @source =~ /^## Vulnerable Application$.+^## Verification Steps$.+^## Options$.+^## Scenarios$/m
      warn('H2 headings in incorrect order.  Should be: Vulnerable Application, Verification Steps, Options, Scenarios')
    end
  end

  def line_checks
    idx = 0
    in_codeblock = false

    @lines.each do |ln|
      idx += 1

      if ln.scan(/```/).length.odd?
        in_codeblock = !in_codeblock
      end

      # find spaces at EOL not in a code block which is ``` or starts with four spaces
      if !in_codeblock && ln =~ /[ \t]$/ && !(ln =~ /^    /)
        warn("Spaces at EOL", idx)
      end

      if ln =~ /^# /
        warn("No H1 (#) headers.  If this is code, indent.", idx)
      end

      l = 140
      if ln.length > l && !in_codeblock
        warn("Line too long (#{ln.length}).  Consider a newline (which resolves to a space in markdown) to break it up around #{l} characters.", idx)
      end

    end
  end

  #
  # Run all the msftidy checks.
  #
  def run_checks
    has_module
    check_start_with_vuln_app
    has_h2_headings
    check_newline_eof
    h2_order
    line_checks
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
        next unless File.extname(full_filepath) == '.md'
        msftidy = MsftidyDoc.new(full_filepath)
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
