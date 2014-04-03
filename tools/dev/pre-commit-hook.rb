#!/usr/bin/env ruby

# Check that modules actually pass msftidy checks first.
# To install this script, make this your pre-commit hook your local
# metasploit-framework clone. For example, if you have checked out
# the Metasploit Framework to:
#
# /home/mcfakepants/git/metasploit-framework
#
# then you will copy this script to:
#
# /home/mcfakepants/git/metasploit-framework/.git/hooks/pre-commit
#
# You must mark it executable (chmod +x), and do not name it
# pre-commit.rb (just pre-commit)
#
# If you want to keep up on changes with this hook, just:
#
# ln -sf <this file> <path to commit hook>

def merge_error_message
  msg = []
  msg << "[*] This merge contains modules failing msftidy.rb"
  msg << "[*] Please fix this if you intend to publish these"
  msg << "[*] modules to a popular metasploit-framework repo"
  puts "-" * 72
  puts msg.join("\n")
  puts "-" * 72
end

valid = true # Presume validity
files_to_check = []

# Who called us? If it's a post-merge check things operate a little
# differently.
puts "[*] Running msftidy.rb in #{$0} mode"

case $0
when /post-merge/
  base_caller = :post_merge
when /pre-commit/
  base_caller = :pre_commit
else
  base_caller = :msftidy
end

if base_caller == :post_merge
  changed_files = %x[git diff --name-only HEAD^ HEAD]
else
  changed_files = %x[git diff --cached --name-only]
end

changed_files.each_line do |fname|
  fname.strip!
  next unless File.exist?(fname) and File.file?(fname)
  next unless fname =~ /modules.+\.rb/
  files_to_check << fname
end

if files_to_check.empty?
  puts "--- No Metasploit modules to check ---"
else
  puts "--- Checking new and changed module syntax with tools/msftidy.rb ---"
  files_to_check.each do |fname|
    cmd = "ruby ./tools/msftidy.rb  #{fname}"
    msftidy_output= %x[ #{cmd} ]
    puts "#{fname} - msftidy check passed" if msftidy_output.empty?
    msftidy_output.each_line do |line|
      valid = false
      puts line
    end
  end
  puts "-" * 72
end

unless valid
  if base_caller == :post_merge
    puts merge_error_message
    exit(0x10)
  else
    puts "[!] msftidy.rb objected, aborting commit"
    puts "[!] To bypass this check use: git commit --no-verify"
    puts "-" * 72
    exit(0x01)
  end

end
