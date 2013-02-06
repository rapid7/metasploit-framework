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

valid = true # Presume validity
files_to_check = []

results = %x[git diff --cached --name-only]

results.each_line do |fname|
  fname.strip!
  next unless File.exist?(fname) and File.file?(fname)
  next unless fname =~ /modules.+\.rb/
  files_to_check << fname
end

if files_to_check.empty?
  puts "--- No Metasploit modules to check, committing. ---"
else
  puts "--- Checking module syntax with tools/msftidy.rb ---"
  files_to_check.each do |fname|
    cmd = "ruby ./tools/msftidy.rb  #{fname}"
    msftidy_output= %x[ #{cmd} ]
    puts "#{fname} - msftidy check passed" if msftidy_output.empty?
    msftidy_output.each_line do |line|
      valid = false
      puts line
    end
  end
  puts "-" * 52
end

unless valid
  puts "msftidy.rb objected, aborting commit"
  puts "To bypass this check use: git commit --no-verify"
  puts "-" * 52
  exit(1)
end
