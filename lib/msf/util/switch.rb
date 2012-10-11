#!/usr/bin/env ruby

require 'find'
require 'fileutils'

module Msf
	module Util
		class SwitchConfig

			SEP = File::SEPARATOR
			GITHUB_SVN = 'https://github.com/rapid7/metasploit-framework/trunk'

			attr_reader :i, :new_svn_checkout, :new_source

			def initialize(i=nil)
				@i = (i || rand(2**16))
				@new_svn_checkout = github_svn_checkout_target
				@new_source = GITHUB_SVN
			end

			def msfbase
				base = __FILE__
				while File.symlink?(base)
					base = File.expand_path(File.readlink(base), File.dirname(base))
				end
				pwd = File.dirname(base)
				File.expand_path(File.join(pwd, "..", "..", ".."))
			end

			def github_svn_checkout_target
				@new_svn_checkout ||= File.join(msfbase, "msf-github-#{@i}")
			end

			def svn_binary
				res = %x|which 'svn'|
				return res.chomp
			end

			def svn_version
				res = %x|#{svn_binary} --version|
				res =~ /version (1\.[0-9\.]+)/
				return $1
			end

			def checkout_cmd
				"svn checkout #{self.new_source} #{self.new_svn_checkout}"
			end


		end
	end
end
