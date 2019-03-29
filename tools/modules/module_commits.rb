#!/usr/bin/env ruby

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

#
# Check the commit history of a module or tree of modules.
# and sort by number of commits.
#
# Usage: tools/module_commits.rb [module dir | module fname]
#

require 'find'

class GitLogLine < Struct.new(:date, :hash, :author, :message)
end

class CommitHistory < Struct.new(:fname, :total, :authors)
end

msfbase = __FILE__
while File.symlink?(msfbase)
  msfbase = File.expand_path(File.readlink(msfbase), File.dirname(msfbase))
end

dir = ARGV[0] || File.join(msfbase, "modules", "exploits")
raise ArgumentError, "Need a filename or directory" unless (dir and File.readable? dir)

def check_commit_history(fname)

  git_cmd = `git log --pretty=format:"%ad %h '%aN' %f" --date=short --date-order #{fname}`
  commit_history = []
  commits_by_author = {}

  git_cmd.each_line do |line|
    parsed_line = line.match(/^([^\s+]+)\s(.{7,})\s'(.*)'\s(.*)[\r\n]*$/)
    commit_history << GitLogLine.new(*parsed_line[1,4])
  end

  commit_history.each do |logline|
    commits_by_author[logline.author] ||= []
    commits_by_author[logline.author] << logline.message
  end

  puts "Commits for #{fname} #{commit_history.size}"
  puts "-" * 72

  commits_by_author.sort_by {|k,v| v.size}.reverse.each do |k,v|
    puts "%-25s %3d" % [k,v.size]
  end

 this_module = CommitHistory.new(fname,commit_history.size,commits_by_author)
 return this_module

end

@module_stats = []

Find.find(dir) do |fname|
  next unless fname =~ /rb$/
  @module_stats << check_commit_history(fname)
end

puts "=" * 72
puts "Sorted modules by commit counts"

@module_stats.sort_by {|m| m.total }.reverse.each do |m|
  puts "%-60s %d" % [m.fname, m.total]
end
