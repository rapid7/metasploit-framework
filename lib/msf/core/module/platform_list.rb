#!/usr/bin/ruby

#
# This is a helper to a easy way to specify support platforms.  It will take a
# list of strings or Msf::Module::Platform objects and build them into a list
# of Msf::Module::Platform objects.  It also supports ranges based on relative
# ranks...
#

require 'Msf/Core/Module/Platform'

class Msf::Module::PlatformList
	attr_accessor :platforms
	def initialize(*args)
		self.platforms = [ ]
		args.each { |a|
			if a.kind_of?(String)
				platforms << Msf::Module::Platform.find_platform(a)
			elsif a.kind_of?(Range)
				b = Msf::Module::Platform.find_platform(a.begin)
				e = Msf::Module::Platform.find_platform(a.end)

				children = Msf::Module::Platform._find_children(b.superclass)
				r        = (b::Rank .. e::Rank)
				children.each { |c|
					platforms << c if r.include?(c::Rank)
				}
			else
				platforms << a
			end

		}
	end

	def names
		platforms.map { |m| m.name.split('::')[3 .. -1].join(' ') }
	end

	# Do I support plist (do I support all of they support?)
	def supports?(plist)
		plist.platforms.each { |pl|
			supported = false
			platforms.each { |p|
				if p >= pl
					supported = true
					break
				end
			}
			return false if !supported
		}

		return true
	end

end

