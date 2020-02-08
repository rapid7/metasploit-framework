#!/usr/bin/env ruby
# -*- coding: binary -*-

#
# Check for data scripts to ensure they are up to date
#
# by h00die
#

require 'digest'
require 'open-uri'
require 'optparse'

options = {}
optparse = OptionParser.new do |opts|
  opts.banner = 'Usage: chececk_external_scripts.rb [options]'
  opts.on('-u', '--update', 'Overwrite old scripts with newer ones.') do
    options[:update] = true
  end
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
  line_msg = ''
  puts "[#{'ERROR'.red}] #{cleanup_text(txt)}"
end

#
# Display a warning message, given some text
#
def warn(txt)
  line_msg = ''
  puts "[#{'WARNING'.yellow}] #{cleanup_text(txt)}"
end

#
# Display a info message, given some text
#
def info(txt)
  line_msg = ''
  puts "[#{'INFO'.cyan}] #{cleanup_text(txt)}"
end

def cleanup_text(txt)
  # remove line breaks
  txt = txt.gsub(/[\r\n]/, ' ')
  # replace multiple spaces by one space
  txt.gsub(/\s{2,}/, ' ')
end

#
#
#  Main
#
#

scripts = []
scripts << {
    'Name' => 'Sharphound (Bloodhound)',
    'address' => 'https://raw.githubusercontent.com/BloodHoundAD/BloodHound/master/Ingestors/SharpHound.ps1',
    'msf_file' => '/data/post/powershell/SharpHound.ps1',
  }

path = File.expand_path('../../', File.dirname(__FILE__))

scripts.each do |script|
  puts "Downloading: #{script['Name']}"
  begin
    content = open(script['address']).read
    new_hash = Digest::SHA1.hexdigest content
    f = open(path + script['msf_file'], 'rb')
    old_hash = Digest::SHA1.hexdigest f.read
    f.close()
    info "Old Hash: #{old_hash}"
    info "New Hash: #{new_hash}"
    unless old_hash == new_hash
      warn "  New version identified!"
      if options[:update] == true
        warn "    Updating MSF copy of #{script['msf_file']}"
        f = open(path + script['msf_file'], 'wb')
        f.write(content)
        f.close()
      end
    end
  rescue OpenURI::HTTPError
    error "Unable to download, check URL: #{script['address']}"
  rescue Errno::ENOENT
    error "msf_file not found, check path: #{path + script['msf_file']}"
  end
end

