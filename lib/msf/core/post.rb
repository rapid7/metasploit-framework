# -*- coding: binary -*-

#
# A Post-exploitation module
#
class Msf::Post < Msf::Module

	require 'msf/core/post/common'
	require 'msf/core/post_mixin'

	require 'msf/core/post/file'

	require 'msf/core/post/linux'
	require 'msf/core/post/osx'
	require 'msf/core/post/solaris'
	require 'msf/core/post/unix'
	require 'msf/core/post/windows'

	include Msf::PostMixin

	def setup; end

	def type
		Msf::MODULE_POST
	end

	def self.type
		Msf::MODULE_POST
	end

	#
	# Create an anonymous module not tied to a file.  Only useful for IRB.
	#
	def self.create(session)
		mod = new
		mod.instance_variable_set(:@session, session)
		# Have to override inspect because for whatever reason, +type+ is coming
		# from the wrong scope and i can't figure out how to fix it.
		mod.instance_eval do
			def inspect
				"#<Msf::Post anonymous>"
			end
		end
		mod.class.refname = "anonymous"

		mod
	end
end
