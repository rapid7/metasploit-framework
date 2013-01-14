# -*- coding: binary -*-
#
# This handles gem requirements for bundled installer environments
#

module Msf
module Env
class Gemcache

	@@msfbase = ::File.expand_path(::File.join(::File.dirname(__FILE__), '..', '..', '..'))
	@@gembase = ::File.join(@@msfbase, "lib/gemcache")
	@@gemarch = ( RUBY_PLATFORM =~ /mingw/ ? 'win32' : ( RUBY_PLATFORM =~ /x86_64.*linux/ ? 'linux64' : (RUBY_PLATFORM =~ /i\d86.*linux/ ? 'linux32' : 'unknown') ) )
	@@rubvers =	'1.9.1'
	@@gempath = "#{@@gembase}/ruby/#{@@rubvers}"

	def self.configure
		return if not ::File.exist?(@@gembase)

		# The gemcache directory is a modified version of the output created by
		# $ bundle install --path=lib/gemcache from within the Pro environment

		ENV['GEM_PATH'] = ENV['GEM_PATH'] ? "#{ENV['GEM_PATH']}:#{@@gempath}" : "#{@@gempath}"
		::Dir["#{@@gempath}/gems/*/lib"].each { |lib| $:.unshift(lib) }

		if ENV['MSF_BUNDLE_BINARY_GEMS'].to_s.downcase =~ /^[yt1]/
			::Dir["#{@@gempath}/arch/#{@@gemarch}/*/lib"].each { |lib| $:.unshift(lib) }
		end

		# Handle a specific corner case where SVN was used to update, but the installer is generation-1
		# This will provide updated binary gems for older installation environments, which is required
		# for framework-trunk to continue working after the ActiveRecord 3 upgrade.

		if ::File.exists?( File.join( File.dirname(__FILE__), "..", "..", "..", "..", "properties.ini") ) and # Installer
		   ::File.directory?( File.join( File.dirname(__FILE__), "..", "..", "..", "..", "apps", "pro") ) and # Confirmed
		   ::File.exists?( File.join( File.dirname(__FILE__), "..", "..", "..", "..", "apps", "pro", "ui", "script", "console") ) # Rails2 artifact
			# Load the arch-old gem directories before the system paths to get an updated pg gem
			::Dir["#{@@gempath}/arch-old/#{@@gemarch}/*/lib"].each { |lib| $:.unshift(lib) }

			# Patch up the gem command to always return true for certain gems
			::Object.class_eval %q|
				def gem(*args)

					return true if [
						'pg'              # Bypass a gem() version call in ActiveRecord
					].include?(args[0])

					super(*args)
				end
			|
		end
	end

end
end
end


Msf::Env::Gemcache.configure
