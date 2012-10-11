#!/usr/bin/env ruby

# The goal here is to switch out the legacy www.metasploit.com
# source and switch over to Github with minimum fuss and minimum
# magic.
#
# This is potentially destructive. Most people shouldn't care too
# much though.
#
# Here's what happens.
# We check out the new subversion repo to a local subdir
# We catch a list of everything that's not checked in.
# We move that stuff down to the subdir
# We delete everything except the new checkout and this file.
# We move everything in the subdir up one level, except this file.
# Celebrate!


require 'find'
require 'fileutils'

class SvnConfig

	SEP = File::SEPARATOR

	def initialize(i=nil)
		@i = i
		new_checkout
	end

	def github_checkout_subdir
		if @i.kind_of? Integer
			"msf-github-#{@i}"
		else
			"msf-github-#{rand(2**16)}"
		end
	end

	def msfbase
		base = __FILE__
		while File.symlink?(base)
			base = File.expand_path(File.readlink(base), File.dirname(base))
		end
		File.dirname(base)
	end

	def new_checkout
		@new_checkout ||= File.expand_path(
			File.join(msfbase, github_checkout_subdir, SEP)
		)
	end

end
