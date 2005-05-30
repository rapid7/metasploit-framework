#!/usr/bin/ruby

#
# This is the definitions of which Platforms the framework knows about.  The
# relative ranks are used to support ranges, and the Short names are used to
# allow for more convenient specification of the platforms....
#

class Msf::Module::Platform

	Rank  = 0
	# actually, having a argument of '' is what to do for wanting 'all'
	Short = "all"

	#
	# The magic to try to build out a Platform from a string
	#
	def self.find_platform(str)
		# remove any whitespace and downcase
		str = str.gsub(' ', '').downcase

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

			begin
				short = c.const_get("Short")
				# it was inherited...
				if short == c.superclass.const_get("Short")
					raise NameError
				end
			rescue NameError
				short = c.const_set("Short", c.name.split('::')[-1][0, 3].downcase)
			end

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
		class X86 < Windows
			Rank  = 100
			class XP < X86
				Rank  = 300
				class SP0 < XP
					Rank  = 100
				end
				class SP1 < XP
					Rank  = 200
				end
				class SP2 < XP
					Rank  = 300
				end
			end
		end
	end
end

