#!/usr/bin/env ruby

require 'find'
require 'fileutils'

module Msf
	module Util

		class SwitchConfig

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

	end
end
