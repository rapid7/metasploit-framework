#!/usr/bin/ruby

#
# This is my overly complex way to specify what platforms different modules
# support.  This can be used to see if an exploit will work against a certain
# platform, or if a payload will work for a certain exploit.
#
# The test for these will be simple, just if a class is equal to or a
# superclass, than it will support.  For example:
# A payload that supports Platform::Windows would support something like
# Platform::Windows::X86::XP::SP0::English.  And something that supported
# Platform::Windows::X86::XP::SP0 would also support this, etc, etc.
#
# We of course will need a nicer way to specify the list since the above
# is annoying and overly verbose.  Hence we will have Platform::Build() to build
# out these object lists in an easier fasion.
#
# Stupid ruby inherits constants, so I couldn't get the auto Short generation
# and caching system to work right.  So for now each Platform needs a Short :(
#

class Msf::Module::PlatformList
	attr_accessor :list
	def initialize(*args)
		self.list = [ ]
		args.each { |a|
			if a.kind_of?(String)
				list << Msf::Module::Platform.find_platform(a)
			elsif a.kind_of?(Range)
				b = Msf::Module::Platform.find_platform(a.begin)
				e = Msf::Module::Platform.find_platform(a.end)

				children = Msf::Module::Platform._find_children(b.superclass)
				r        = (b::Rank .. e::Rank)
				children.each { |c|
					list << c if r.include?(c::Rank)
				}
			else
				list << a
			end

		}
	end

end

class Msf::Module::Platform

	#
	# The magic to try to build out a Platform from a string
	#
	def self.find_platform(str)
		# remove any whitespace and downcase
		str = str.sub(' ', '').downcase

		mod = Msf::Module::Platform

		while str.length > 0
			mod, str = _find_short(mod, str)
		end

		return mod
	end

	# this is useful a lot of places, and should go into some
	# library somewhere, or something
	def self._find_children(mod)
		mod.constants.map { |n| mod.const_get(n) }.
		  delete_if { |v| ! v.kind_of?(Class) || ! (v < mod) }
	end

	# make private! I forget how! I suck!
	def self._find_short(base, name)
		# get a list of possible base classes, and sort them by
		# their relative ranks to each other
		poss = _find_children(base).sort { |a, b| a::Rank <=> b::Rank }

		if poss.empty?
			raise ArgumentError, "No classes in #{base.to_s}!", caller
		end

		best    = nil
		bestlen = 0

		poss.each { |c|
			# Try to get the short "nick" name, aka win vs Windows.
			# If there is no shortname, generate one and cache it.
			# Generation is atmost the first 3 chars downcased..

			short = c.const_get("Short")

			if short.length > bestlen && name[0, short.length] == short
				best = [ c, name[short.length .. -1] ]
				bestlen = short.length
			end
		}

		if !best
			# ok, no match, fall back on first ranked
			best = [ poss[0], name ]
		end

		return best

	end


	class Windows < Msf::Module::Platform
		Rank  = 100
		Short = 'win'
		class X86 < Windows
			Rank  = 100
			Short = 'x86'
			class XP < X86
				Rank  = 300
				Short = 'xp'
				class SP0 < XP
					Rank  = 100
					Short = 'sp0'
				end
				class SP1 < XP
					Rank  = 200
					Short = 'sp1'
				end
				class SP2 < XP
					Rank  = 300
					Short = 'sp2'
				end
			end
		end
	end
end

