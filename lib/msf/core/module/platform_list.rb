#!/usr/bin/env ruby

#
# This is a helper to a easy way to specify support platforms.  It will take a
# list of strings or Msf::Module::Platform objects and build them into a list
# of Msf::Module::Platform objects.  It also supports ranges based on relative
# ranks...
#

require 'msf/core/module/platform'

class Msf::Module::PlatformList
	attr_accessor :platforms

	#
	# Returns the win32 platform list.
	#
	def self.win32
		transform('win')
	end

	#
	# Transformation method, just accept an array or a single entry.
	# This is just to make defining platform lists in a module more
	# convenient, skape's a girl like that.
	#
	def self.transform(src)
		if (src.kind_of?(Array))
			from_a(src)
		else
			from_a([src])
		end
	end

	#
	# Create an instance from an array
	#
	def self.from_a(ary)
		self.new(*ary)
	end

	#
	# Constructor, takes the entries are arguments
	#
	def initialize(*args)
		self.platforms = [ ]

		args.each { |a|
			if a.kind_of?(String)
				platforms << Msf::Module::Platform.find_platform(a)
			elsif a.kind_of?(Range)
				b = Msf::Module::Platform.find_platform(a.begin)
				e = Msf::Module::Platform.find_platform(a.end)

				children = b.superclass.find_children
				r        = (b::Rank .. e::Rank)
				children.each { |c|
					platforms << c if r.include?(c::Rank)
				}
			else
				platforms << a
			end

		}

	end

	#
	# Checks to see if the platform list is empty.
	#
	def empty?
		return platforms.empty?
	end

	#
	# Returns an array of names contained within this platform list.
	#
	def names
		platforms.map { |m| m.realname }
	end

	#
	# Symbolic check to see if this platform list represents 'all' platforms.
	#
	def all?
		names.each do |name|
			return true if name == ''
		end
		return false
	end

	#
	# Do I support plist (do I support all of they support?)
	# use for matching say, an exploit and a payload
	#
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

	#
	# WARNING: I pulled this algorithm out of my ass, it's probably broken
	#
	# Ok, this was a bit weird, but I think it should work.  We basically
	# want to do a set intersection, but with like superset expansion or
	# something or another.  So I try to do that recursively, and the
	# result should be a the valid platform intersection...
	#
	# used for say, building a payload from a stage and stager
	#
	def &(plist)
		list1 = plist.platforms
		list2 = platforms
		total = [ ]

		# If either list has all in it, just merge the two
		if (plist.all? or all?)
			return list1.dup.concat(list2)
		end

		#
		# um, yeah, expand the lowest depth (like highest superset)
		# each time and then do another intersection, keep doing
		# this until no one has any children anymore...
		#

		loop do
			# find any intersections
			inter = list1 & list2
			# remove them from the two sides
			list1 = list1 - inter
			list2 = list2 - inter
			# add them to the total
			total += inter

			if list1.empty? || list2.empty?
				break
			end

			begin
				list1, list2 = _intersect_expand(list1, list2)
			rescue ::RuntimeError
				break
			end
		end

		return Msf::Module::PlatformList.new(*total)
	end

	protected

	#
	# man this be ghetto.  Expand the 'superest' set of the two lists.
	# will only ever expand 1 set, excepts both sets to already have
	# been intersected with each other..
	#
	def _intersect_expand(list1, list2)
		(list1 + list2).sort { |a, b|
		  a.name.split('::').length <=> b.name.split('::').length }.
		  each { |m|
		  	children = m.find_children
			if !children.empty?
				if list1.include?(m)
					return [ list1 - [ m ] + children, list2 ]
				else
					return [ list1, list2 - [ m ] + children ]
				end
			end
		}

		# XXX what's a better exception to throw here?
		raise RuntimeError, "No more expansion possible", caller
	end

end