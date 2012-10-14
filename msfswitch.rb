#!/usr/bin/env ruby

require 'find'
require 'fileutils'

new_subdir = "ghnew-1234"

msfbase = '/tmp/svn-tests/metasploit-svn/trunk' + File::SEPARATOR
new_checkout = File.join(msfbase, new_subdir, File::SEPARATOR)
i = 0

new_svn_dirs = []
old_svn_dirs = []
puts "Finding .svn dirs"
Find.find(msfbase) do |path|
	next unless File.directory? path
	next unless path =~ /\.svn$/
	if path =~ /ghnew-1234/
		fullpath = File.expand_path(path)
		new_svn_dirs << fullpath
		next
	end
	fullpath = File.expand_path(path)
	old_svn_dirs << fullpath
end

puts "Old: #{old_svn_dirs.size} New: #{new_svn_dirs.size}"

puts "Matching up source and dest..."

new_svn_dirs.each do |new_path|
	old_svn_dirs.each_with_index do |old_path,i|
		if old_path == new_path.gsub(/#{new_subdir + File::SEPARATOR}/,"")
			FileUtils.rm_rf(old_path)
			FileUtils.cp_r(new_path, old_path)
			puts "Copied #{new_path}"
			old_svn_dirs.delete_at i
			break
		end
	end
end

puts "Deleting the remaining empty dirs"

old_svn_dirs.each do |old_path|
	FileUtils.rm_rf old_path.gsub(/.svn$/,"")
end

puts "Removing the temp checkout"

FileUtils.rm_rf new_checkout

puts "SVN reverting against GitHub"

puts "Base is #{msfbase}"

res = system("svn", "revert", "--recursive", msfbase )
puts "Results: #{res.inspect}"
res = system("svn", "update", "--recursive", msfbase )
puts "Results: #{res.inspect}"

