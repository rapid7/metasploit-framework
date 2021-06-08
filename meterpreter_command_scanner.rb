#!/usr/bin/env ruby
#  meterpreter_command_scanner.rb
#
# This script is used for analyzing Metasploit Framework library and module source code files to identify references to
# the Meterpreter API. Originally implemented in support of https://github.com/rapid7/metasploit-framework/pull/15079.
#

require 'find'

# These are ignored because they do not invoke a Meterpreter command.
IGNORE = %w{
  .arch
  .commands*
  .native_arch
  .platform
  .response_timeout
  .respond_to
  .shell_command
  .session_*
  .sock.*
  .target_host
  .type
}

def scan_directory(directory_path)
  Find.find(directory_path).each do |path|
    if File.directory?(path)
      next if path == directory_path
      scan_directory(path)
    else
      scan_file(path)
    end
  end
end

def scan_file(file_path)
  unless File.readable?(file_path)
    $stderr.puts "[-] can not read file: #{file_path}"
    return
  end

  contents = File.read(file_path)
  matches = []
  contents.to_enum(:scan, /\W(?<value>(client|session)(?<attribute>(\.\w+)+))\W/).map do |_|
    match = Regexp.last_match
    
    next if IGNORE.any? { |ignore| File.fnmatch(ignore, match[:attribute]) }
    
    matches << {
      line: contents[0..Regexp.last_match.begin(0)].count("\n") + 1,
      value: match[:value]
    }
  end

  matches.sort_by! { |match| match[:line] }
  matches.uniq! { |match| match[:value] }

  matches.each do |match|
    puts "#{(file_path + ':' + match[:line].to_s).ljust(50)} #{match[:value]}"
    puts "\n"
  end
end

def main
  if ARGV.length < 1
    puts "[-] usage: #{__FILE__} [file ...]"
    return
  end

  ARGV.each do |path|
    if File.directory?(path)
      scan_directory(path)
    else
      scan_file(path)
    end
  end
end

main
