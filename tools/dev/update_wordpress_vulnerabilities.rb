#!/usr/bin/env ruby
# -*- coding: binary -*-

#
# Update modules/auxiliary/scanner/http/wordpress_scanner.rb to have the most
# up to date list of vuln compontents based on exploits/scanners in the framework
#
# by h00die
#

require 'optparse'

options = {}
optparse = OptionParser.new do |opts|
  opts.banner = 'Usage: update_wordpress_vulnerabilities.rb [options]'
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

def cleanup_text(txt)
  # remove line breaks
  txt = txt.gsub(/[\r\n]/, ' ')
  # replace multiple spaces by one space
  txt.gsub(/\s{2,}/, ' ')
end

plugins = []
themes = []
path = File.expand_path('../../', File.dirname(__FILE__))
Dir.glob(path + '/modules/**/*.rb').each do |file|
  next unless file.include?('exploits') || file.include?('auxiliary')

  str = IO.read(file)
  match = str.match(/check_plugin_version_from_readme\(['"]([^'"]+)['"]/)
  unless match.nil?
    plugins.append(match[1])
    info("#{file} contains plugin '#{match[1]}'")
  end
  match = str.match(/check_theme_version_from_readme\(['"]([^'"]+)['"]/)
  unless match.nil?
    themes.append(match[1])
    info("#{file} contains theme '#{match[1]}'")
  end
end

info('Updating wp-exploitable-themes.txt')
wp_list = path + '/data/wordlists/wp-exploitable-themes.txt'

File.open(wp_list, 'w+') do |f|
  f.puts(themes)
end

info('Updating wp-exploitable-plugins.txt')
wp_list = path + '/data/wordlists/wp-exploitable-plugins.txt'

File.open(wp_list, 'w+') do |f|
  f.puts(plugins)
end
