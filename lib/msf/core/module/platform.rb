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

class Msf::Module::Platform

	#
	# The magic to try to build out a Platforms array from strings
	#
	def self.build(*strs)

	end

	# make private! I forget how! I suck!
	def self._find_short(base, name)
		# get a list of possible base classes, and sort them by
		# their relative ranks to each other
		poss = base.constants.map { |n| base.const_get(n) }.
		  delete_if { |v| !v.kind_of?(Class) }.
		  sort { |a, b| a::RANK <=> b::RANK }

		if poss.empty?
			raise ArgumentError, "No classes in #{base.to_s}!", caller
		end

		poss.each { |c|
			# Try to get the short "nick" name, aka win vs Windows.
			# If there is no shortname, generate one and cache it.
			# Generation is atmost the first 3 chars downcased..
			begin
				short = c.const_get("SHORT")
			rescue NameError
				short = c.const_set("SHORT", c.name.split('::')[-1][0, 3].downcase)
			end

			if name[0, short.length] == short
				return [ c, name[short.length .. -1] ]
			end
		}

		# ok, no match, fall back on first ranked
		return [ poss[0], name ]

	end


	class Windows < Msf::Module::Platform
		class X86 < Windows
			RANK = 100
			class XP < X86
				class SP0 < XP
					RANK = 100
				end
				class SP1 < XP
					RANK = 200
				end
				class SP2 < XP
					RANK = 300
				end
			end
		end
	end
end

