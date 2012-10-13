#!/usr/bin/env ruby

require 'find'
require 'fileutils'

module Msf
	module Util

		class SvnSwitchConfig

			SEP = File::SEPARATOR
			GITHUB_SVN = 'https://github.com/rapid7/metasploit-framework'

			attr_reader :i, :new_svn_checkout, :new_source, :msfbase

			def initialize(i=nil, base=nil)
				@i = (i || rand(2**16))
				self.msfbase = base
				@new_svn_checkout = github_svn_checkout_target
				@new_source = GITHUB_SVN
			end

			def resolve_symlink(fname)
				while File.symlink?(fname)
					fname = File.expand_path(File.readlink(fname), File.dirname(fname))
				end
				return fname
			end

			def msfbase
				return @msfbase if @msfbase
				pwd = File.dirname(__FILE__)
				self.msfbase = File.expand_path(File.join(pwd, "..", "..", ".."))
			end

			def msfbase=(path=nil)
				@msfbase = nil
				@msfbase = resolve_symlink (path || msfbase)
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
				cmd = [svn_binary]
				cmd += ["checkout", "--non-recursive"]
				cmd << self.new_source
				cmd << self.new_svn_checkout
			end

			def cleanup_cmd
				cmd = [svn_binary]
				cmd += ["cleanup"]
				cmd << self.new_svn_checkout
			end

			def cleanup_current_cmd
				cmd = [svn_binary]
				cmd += ["cleanup"]
				cmd << self.msfbase
			end

			def stage_cmd
				cmd = [svn_binary]
				cmd << "update"
				cmd << "--non-recursive"
				cmd << [self.new_svn_checkout,SEP,"trunk"].join
			end

			def update_cmd
				cmd = [svn_binary]
				cmd << "update"
				cmd << "--set-depth"
				cmd << "infinity"
				cmd << [self.new_svn_checkout,SEP,"trunk"].join
			end

			def info_cmd
				cmd = [svn_binary]
				cmd << "info"
				cmd << [self.new_svn_checkout,SEP,"trunk"].join
			end

			def revert_cmd
				cmd = [svn_binary]
				cmd << "revert"
				cmd << [self.new_svn_checkout,SEP,"trunk"].join
			end

			def status_current_cmd
				cmd = [svn_binary]
				cmd << "status"
				cmd << self.msfbase
			end

			def locally_modified_files
				return @eligable_results if @eligable_results
				cmd = "#{svn_binary} status '#{self.msfbase}'"	
				results = %x[#{cmd}].split(/\n/)
				okay_to_copy = results.select {|line| line[0,1] =~ /[ACIMR?]/}
				@eligable_results = okay_to_copy.map {|line| line[8,line.size]}
			end

			def switchable?
				cmd = "#{svn_binary} status '#{self.msfbase}'"	
				results = %x[#{cmd}].split(/\n/)
				results.map {|line| line[8,line.size]} == locally_modified_files
			end

		end

		class SvnSwitch

			SEP = File::SEPARATOR

			attr_reader :config

			def initialize(i=nil, base=nil)
				@config = SvnSwitchConfig.new(i,base)
			end

			def msfbase
				@config.msfbase
			end

			# Pass args as a *array to protect against spaces
			def system(arg)
				raise ArgumentError unless arg.kind_of? Symbol
				raise ArgumentError unless arg.to_s =~ /_cmd$/
				raise ArgumentError unless @config.respond_to? arg
				cmd = @config.send arg
				# $stderr.puts "[!] #{cmd.join(' ')}"
				::Kernel.system(*cmd)
			end

			def delete_new_svn_checkout
				FileUtils.rm_rf self.config.new_svn_checkout
			end

		end

	end
end

