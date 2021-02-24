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
require 'tempfile'

options = {}
optparse = OptionParser.new do |opts|
  opts.banner = 'Usage: check_external_scripts.rb [options]'
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

def cleanup_sqlmap_decloak_dir
  unless system('rm -rf /tmp/sqlmap_decloak')
    error 'Could not remove existing /tmp/sqlmap_decloak directory'
  end
end

def clone_sqlmap_decloak
  cleanup_sqlmap_decloak_dir
  unless system('git clone -q --depth=1 https://github.com/sqlmapproject/sqlmap.git /tmp/sqlmap_decloak')
    error "Either 'git' is not installed, your internet is not connected, or /tmp/sqlmap_decloak could not be removed."
  end
end

# https://github.com/rapid7/metasploit-framework/pull/13191#issuecomment-626584689
def decloak(file)
  unless system("python /tmp/sqlmap_decloak/extra/cloak/cloak.py -d -i #{file.path} -o #{file.path}_decloak")
    unless system("python3 /tmp/sqlmap_decloak/extra/cloak/cloak.py -d -i #{file.path} -o #{file.path}_decloak")
      error "Either python is not installed, or the file at #{file.path} could not be found! Please double check your computer's setup and check that the #{file.path} file exists!"
    end
  end
  File.binread("#{file.path}_decloak")
end

#
#
#  Main
#
#

scripts = []

###
# Bloodhound/Sharphound files
###

# https://github.com/BloodHoundAD/BloodHound/commit/b6ab5cd369c70219c6376d9f5c4fcd63f34fb4a0
scripts << {
  name: 'Sharphound (Bloodhound) ps1',
  addr: 'https://raw.githubusercontent.com/BloodHoundAD/BloodHound/master/Collectors/SharpHound.ps1',
  dest: '/data/post/powershell/SharpHound.ps1',
  subs: [
    ["\t", '    '], # tabs to spaces
    [/\s+$/, ''] # trailing whitespace
  ]
}
scripts << {
  name: 'Sharphound (Bloodhound) exe',
  addr: 'https://raw.githubusercontent.com/BloodHoundAD/BloodHound/master/Collectors/SharpHound.exe',
  dest: '/data/post/SharpHound.exe',
  subs: []
}
###
# JTR files
###
scripts << {
  name: 'JTR - dumb16.conf',
  addr: 'https://raw.githubusercontent.com/magnumripper/JohnTheRipper/bleeding-jumbo/run/dumb16.conf',
  dest: '/data/jtr/dumb16.conf',
  subs: []
}
scripts << {
  name: 'JTR - alnumspace.chr',
  addr: 'https://raw.githubusercontent.com/magnumripper/JohnTheRipper/bleeding-jumbo/run/alnumspace.chr',
  dest: '/data/jtr/alnumspace.chr',
  subs: []
}
scripts << {
  name: 'JTR - regex_alphabets.conf',
  addr: 'https://raw.githubusercontent.com/magnumripper/JohnTheRipper/bleeding-jumbo/run/regex_alphabets.conf',
  dest: '/data/jtr/regex_alphabets.conf',
  subs: []
}
scripts << {
  name: 'JTR - latin1.chr',
  addr: 'https://raw.githubusercontent.com/magnumripper/JohnTheRipper/bleeding-jumbo/run/latin1.chr',
  dest: '/data/jtr/latin1.chr',
  subs: []
}
scripts << {
  name: 'JTR - lowerspace.chr',
  addr: 'https://raw.githubusercontent.com/magnumripper/JohnTheRipper/bleeding-jumbo/run/lowerspace.chr',
  dest: '/data/jtr/lowerspace.chr',
  subs: []
}
scripts << {
  name: 'JTR - utf8.chr',
  addr: 'https://raw.githubusercontent.com/magnumripper/JohnTheRipper/bleeding-jumbo/run/utf8.chr',
  dest: '/data/jtr/utf8.chr',
  subs: []
}
scripts << {
  name: 'JTR - john.conf',
  addr: 'https://raw.githubusercontent.com/magnumripper/JohnTheRipper/bleeding-jumbo/run/john.conf',
  dest: '/data/jtr/john.conf',
  subs: []
}
scripts << {
  name: 'JTR - dumb32.conf',
  addr: 'https://raw.githubusercontent.com/magnumripper/JohnTheRipper/bleeding-jumbo/run/dumb32.conf',
  dest: '/data/jtr/dumb32.conf',
  subs: []
}
scripts << {
  name: 'JTR - alpha.chr',
  addr: 'https://raw.githubusercontent.com/magnumripper/JohnTheRipper/bleeding-jumbo/run/alpha.chr',
  dest: '/data/jtr/alpha.chr',
  subs: []
}
scripts << {
  name: 'JTR - dynamic.conf',
  addr: 'https://raw.githubusercontent.com/magnumripper/JohnTheRipper/bleeding-jumbo/run/dynamic.conf',
  dest: '/data/jtr/dynamic.conf',
  subs: []
}
scripts << {
  name: 'JTR - repeats32.conf',
  addr: 'https://raw.githubusercontent.com/magnumripper/JohnTheRipper/bleeding-jumbo/run/repeats32.conf',
  dest: '/data/jtr/repeats32.conf',
  subs: []
}
scripts << {
  name: 'JTR - lm_ascii.chr',
  addr: 'https://raw.githubusercontent.com/magnumripper/JohnTheRipper/bleeding-jumbo/run/lm_ascii.chr',
  dest: '/data/jtr/lm_ascii.chr',
  subs: []
}
scripts << {
  name: 'JTR - upper.chr',
  addr: 'https://raw.githubusercontent.com/magnumripper/JohnTheRipper/bleeding-jumbo/run/upper.chr',
  dest: '/data/jtr/upper.chr',
  subs: []
}
scripts << {
  name: 'JTR - lowernum.chr',
  addr: 'https://raw.githubusercontent.com/magnumripper/JohnTheRipper/bleeding-jumbo/run/lowernum.chr',
  dest: '/data/jtr/lowernum.chr',
  subs: []
}
scripts << {
  name: 'JTR - ascii.chr',
  addr: 'https://raw.githubusercontent.com/magnumripper/JohnTheRipper/bleeding-jumbo/run/ascii.chr',
  dest: '/data/jtr/ascii.chr',
  subs: []
}
scripts << {
  name: 'JTR - dynamic_disabled.conf',
  addr: 'https://raw.githubusercontent.com/magnumripper/JohnTheRipper/bleeding-jumbo/run/dynamic_disabled.conf',
  dest: '/data/jtr/dynamic_disabled.conf',
  subs: []
}
scripts << {
  name: 'JTR - hybrid.conf',
  addr: 'https://raw.githubusercontent.com/magnumripper/JohnTheRipper/bleeding-jumbo/run/hybrid.conf',
  dest: '/data/jtr/hybrid.conf',
  subs: []
}
scripts << {
  name: 'JTR - repeats16.conf',
  addr: 'https://raw.githubusercontent.com/magnumripper/JohnTheRipper/bleeding-jumbo/run/repeats16.conf',
  dest: '/data/jtr/repeats16.conf',
  subs: []
}
scripts << {
  name: 'JTR - digits.chr',
  addr: 'https://raw.githubusercontent.com/magnumripper/JohnTheRipper/bleeding-jumbo/run/digits.chr',
  dest: '/data/jtr/digits.chr',
  subs: []
}
scripts << {
  name: 'JTR - uppernum.chr',
  addr: 'https://raw.githubusercontent.com/magnumripper/JohnTheRipper/bleeding-jumbo/run/uppernum.chr',
  dest: '/data/jtr/uppernum.chr',
  subs: []
}
scripts << {
  name: 'JTR - lanman.chr',
  addr: 'https://raw.githubusercontent.com/magnumripper/JohnTheRipper/bleeding-jumbo/run/lanman.chr',
  dest: '/data/jtr/lanman.chr',
  subs: []
}
scripts << {
  name: 'JTR - dynamic_flat_sse_formats.conf',
  addr: 'https://raw.githubusercontent.com/magnumripper/JohnTheRipper/bleeding-jumbo/run/dynamic_flat_sse_formats.conf',
  dest: '/data/jtr/dynamic_flat_sse_formats.conf',
  subs: []
}
scripts << {
  name: 'JTR - alnum.chr',
  addr: 'https://raw.githubusercontent.com/magnumripper/JohnTheRipper/bleeding-jumbo/run/alnum.chr',
  dest: '/data/jtr/alnum.chr',
  subs: []
}
scripts << {
  name: 'JTR - lower.chr',
  addr: 'https://raw.githubusercontent.com/magnumripper/JohnTheRipper/bleeding-jumbo/run/lower.chr',
  dest: '/data/jtr/lower.chr',
  subs: []
}
scripts << {
  name: 'JTR - korelogic.conf',
  addr: 'https://raw.githubusercontent.com/magnumripper/JohnTheRipper/bleeding-jumbo/run/korelogic.conf',
  dest: '/data/jtr/korelogic.conf',
  subs: []
}

###
# SQLMap UDF files
###
scripts << {
  name: 'SQLMap UDF - lib_mysqludf_sys_32.so',
  addr: 'https://github.com/sqlmapproject/sqlmap/blob/master/data/udf/mysql/linux/32/lib_mysqludf_sys.so_?raw=true',
  dest: '/data/exploits/mysql/lib_mysqludf_sys_32.so',
  subs: []
}
scripts << {
  name: 'SQLMap UDF - lib_mysqludf_sys_64.so',
  addr: 'https://github.com/sqlmapproject/sqlmap/blob/master/data/udf/mysql/linux/64/lib_mysqludf_sys.so_?raw=true',
  dest: '/data/exploits/mysql/lib_mysqludf_sys_64.so',
  subs: []
}
scripts << {
  name: 'SQLMap UDF - lib_mysqludf_sys_32.dll',
  addr: 'https://github.com/sqlmapproject/sqlmap/blob/master/data/udf/mysql/windows/32/lib_mysqludf_sys.dll_?raw=true',
  dest: '/data/exploits/mysql/lib_mysqludf_sys_32.dll',
  subs: []
}
scripts << {
  name: 'SQLMap UDF - lib_mysqludf_sys_64.dll',
  addr: 'https://github.com/sqlmapproject/sqlmap/blob/master/data/udf/mysql/windows/64/lib_mysqludf_sys.dll_?raw=true',
  dest: '/data/exploits/mysql/lib_mysqludf_sys_64.dll',
  subs: []
}

###
# CMS Files
###

# https://github.com/rapid7/metasploit-framework/pull/11862#issuecomment-496578367
scripts << {
  name: 'WordPress - Plugins List',
  addr: 'https://plugins.svn.wordpress.org',
  dest: '/data/wordlists/wp-plugins.txt',
  subs: [
    [/^((?!  <li>).)*/, ''], # remove all non-plugin lines
    [/  <li><a href="[^"]+">/, ''], # remove beginning
    [/\/<\/a><\/li>/,''], # remove end
    [/^\s*/,''] # remove empty lines
  ]
}

scripts << {
  name: 'WordPress - Themes List',
  addr: 'https://themes.svn.wordpress.org',
  dest: '/data/wordlists/wp-themes.txt',
  subs: [
    [/^((?!  <li>).)*/, ''], # remove all non-plugin lines
    [/  <li><a href="[^"]+">/, ''], # remove beginning
    [/\/<\/a><\/li>/,''], # remove end
    [/^\s*/,''] # remove empty lines
  ]
}

# Joomla's is more complicated. It looks for more than
# just components.  Because of that, if you want the
# file updated, see:
# https://github.com/rapid7/metasploit-framework/pull/11199#issue-242415518
# python3 tools/dev/update_joomla_components.py

path = File.expand_path('../../', File.dirname(__FILE__))

clone_sqlmap_decloak

scripts.each do |script|
  puts "Downloading: #{script[:name]}"
  begin
    old_content = File.binread(path + script[:dest])
    old_hash = Digest::SHA1.hexdigest old_content
    info "Old Hash: #{old_hash}"

    new_content = URI.open(script[:addr]).read
    if script.key?(:subs)
      script[:subs].each do |sub|
        new_content.gsub!(sub[0], sub[1])
      end
    end

    if script[:name].start_with?('SQLMap UDF')
      info('Performing decloaking')
      f = Tempfile.new('sqlmap_udf')
      f.write(new_content)
      f.close
      new_content = decloak(f)
    end

    new_hash = Digest::SHA1.hexdigest new_content
    info "New Hash: #{new_hash}"

    unless old_hash == new_hash
      warning '  New version identified!'
      if options[:update] == true
        warning "    Updating MSF copy of #{script[:dest]}"
        File.binwrite(path + script[:dest], new_content)
      end
    end
  rescue OpenURI::HTTPError
    error "Unable to download, check URL: #{script[:addr]}"
  rescue Errno::ENOENT
    error "Destination not found, check path: #{path + script[:dest]}"
  end
end

cleanup_sqlmap_decloak_dir
