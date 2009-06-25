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
		names.include? ''
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
		# If either list has all in it, return the other one
		if plist.all?
			return self
		elsif self.all?
			return plist
		end

		list1 = plist.platforms
		list2 = platforms
		total = []

		loop do
			# find any intersections
			inter = list1 & list2
			# remove them from the two sides
			list1 -= inter
			list2 -= inter
			# add them to the total
			total += inter

			break if list1.empty? || list2.empty?

			# try to expand to subclasses to refine the match
			break if ! _intersect_expand(list1, list2)
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
		# abort if no shared prefix is found between l1 and l2
		# shortcircuits [Windows] & [Linux] without going
		#  through XP => SP2 => DE
		ln1 = list1.map { |c| c.name }
		ln2 = list2.map { |c| c.name }
		return if not ln1.find { |n1|
			ln2.find { |n2| n1[0, n2.length] == n2[0, n1.length] }
		}

		(list1 + list2).sort { |a, b|
			# find the superest class in both lists
			a.name.count(':') <=> b.name.count(':')
		}.find { |m|
			# which has children
		  	children = m.find_children
			next if children.empty?
			# replace this class in its list by its children
			l = list1.include?(m) ? list1 : list2
			l.delete m
			l.concat children
			true
		}
	end

end