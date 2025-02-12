#!/usr/bin/env ruby
# -*- coding: binary -*-

#
# by h00die
#

require 'optparse'
require 'net/http'
require 'uri'
optparse = OptionParser.new do |opts|
  opts.banner = 'Usage: ruby tools/dev/update_joomla_components.rb [options]'
  opts.separator "This program updates data/wordlists/joomla.txt which is used by modules/auxiliary/scanner/http/joomla_scanner.rb to have the most up-to-date list of vuln components"
  opts.separator ""
  opts.on('-h', '--help', 'Display this screen.') do
    puts opts
    exit
  end
end
optparse.parse!

# colors and puts templates from msftidy.rb

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

#
# Display an error message, given some text
#
def error(txt)
  puts "[#{'ERROR'.red}] #{cleanup_text(txt)}"
end

#
# Display a warning message, given some text
#
def warning(txt)
  puts "[#{'WARNING'.yellow}] #{cleanup_text(txt)}"
end

#
# Display a info message, given some text
#
def info(txt)
  puts "[#{'INFO'.cyan}] #{cleanup_text(txt)}"
end

uri = URI.parse('https://raw.githubusercontent.com/rezasp/joomscan/master/exploit/db/componentslist.txt')
new_com = Net::HTTP.get(uri)

old = File.read('data/wordlists/joomla.txt').split("\n")

new_com.each_line do |com|
  unless old.include?("components/#{com.strip}/")
    old << "components/#{com.strip}/"
    info "Adding: components/#{com.strip}/"
  end
end

old.sort!
File.open('data/wordlists/joomla.txt', 'w') do |file|
  file.puts old
end