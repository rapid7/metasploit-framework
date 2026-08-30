#!/usr/bin/env ruby
# -*- coding: binary -*-

require 'optparse'
require 'net/http'
require 'uri'
optparse = OptionParser.new do |opts|
  opts.banner = 'Usage: ruby tools/dev/update_user_agent_strings.rb [options]'
  opts.separator "This program updates lib/rex/user_agent.rb so Metasploit uses the most up-to-date User Agent strings across the framework."
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

def cleanup_text(txt)
  # remove line breaks
  txt = txt.gsub(/[\r\n]/, ' ')
  # replace multiple spaces by one space
  txt.gsub(/\s{2,}/, ' ')
end

def replace_agent_string(lines, replace_marker, url, regex)
  valid_chars = 'a-zA-Z0-9\(\);:\.,/_ '
  regex = regex.gsub('{VALID_CHARS}', valid_chars)
  info "Checking: #{replace_marker}"

  index = lines.index { |line| line.include?(replace_marker) }
  raise "Couldn't find marker #{replace_marker}" if index.nil?

  uri = URI(url)
  response = Net::HTTP.get_response(uri)
  raise "Can't retrieve #{url}" unless response.is_a?(Net::HTTPSuccess)

  match = response.body.match(/#{regex}/)
  raise "Couldn't match regex #{regex}" if match.nil?

  new_string = match[1]

  old_line = lines[index]
  if old_line.include?("'#{new_string}'")
    puts "  (Unchanged): #{new_string}"
  else
    new_line = old_line.gsub(/'(.*)'/, "'#{new_string}'")
    if old_line == new_line
      raise "  Line didn't change: #{old_line}"
    end
    puts "  New value is: #{new_string}"
    lines[index] = new_line
  end
end

chrome_url = "https://www.whatismybrowser.com/guides/the-latest-user-agent/chrome"
edge_url = "https://www.whatismybrowser.com/guides/the-latest-user-agent/edge"
safari_url = "https://www.whatismybrowser.com/guides/the-latest-user-agent/safari"
firefox_url = "https://www.whatismybrowser.com/guides/the-latest-user-agent/firefox"

user_agent_filename = 'lib/rex/user_agent.rb'
lines = File.read(user_agent_filename).split("\n")

replace_agent_string(lines, 'Chrome Windows', chrome_url, '<td>Chrome \\(Standard\\)</td>\s*<td>\s*<ul>\s*<li><span class="code">([{VALID_CHARS}]*Windows NT[{VALID_CHARS}]*)</span>')
replace_agent_string(lines, 'Chrome MacOS', chrome_url, '<td>Chrome \\(Standard\\)</td>\s*<td>\s*<ul>\s*<li><span class="code">([{VALID_CHARS}]*Macintosh[{VALID_CHARS}]*)</span>')
replace_agent_string(lines, 'Edge Windows', edge_url, '<td>Edge \\(Standard\\)</td>\s*<td>\s*<ul>\s*<li><span class="code">([{VALID_CHARS}]*Windows NT[{VALID_CHARS}]*)</span>')
replace_agent_string(lines, 'Safari iPad', safari_url, '<td>\s*Safari on <b>Ipad</b>\s*</td>\s*<td>\s*<ul>\s*<li><span class="code">([{VALID_CHARS}]*iPad[{VALID_CHARS}]*)</span>')
replace_agent_string(lines, 'Safari MacOS', safari_url, '<td>Safari \\(Standard\\)</td>\s*<td>\s*<ul>\s*<li><span class="code">([{VALID_CHARS}]*Macintosh[{VALID_CHARS}]*)</span>')
replace_agent_string(lines, 'Firefox Windows', firefox_url, '<td>\s*Firefox on <b>Windows</b>\s*</td>\s*<td>\s*<ul>\s*<li><span class="code">([{VALID_CHARS}]*Windows NT[{VALID_CHARS}]*)</span>')
replace_agent_string(lines, 'Firefox MacOS', firefox_url, '<td>\s*Firefox on <b>Macos</b>\s*</td>\s*<td>\s*<ul>\s*<li><span class="code">([{VALID_CHARS}]*Macintosh[{VALID_CHARS}]*)</span>')

File.write(user_agent_filename, lines.join("\n") + "\n")
