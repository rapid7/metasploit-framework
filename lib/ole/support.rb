# 
# A file with general support functions used by most files in the project.
# 
# These are the only methods added to other classes.
# 

require 'logger'
require 'stringio'
require 'enumerator'

class String # :nodoc:
	# plural of String#index. returns all offsets of +string+. rename to indices?
	#
	# note that it doesn't check for overlapping values.
	def indexes string
		# in some ways i'm surprised that $~ works properly in this case...
		to_enum(:scan, /#{Regexp.quote string}/m).map { $~.begin 0 }
	end

	def each_chunk size
		(length / size.to_f).ceil.times { |i| yield self[i * size, size] }
	end
end

class File # :nodoc:
	# for interface consistency with StringIO etc (rather than adding #stat
	# to them). used by RangesIO.
	def size
		stat.size
	end
end

class Symbol # :nodoc:
	unless :x.respond_to? :to_proc
		def to_proc
			proc { |a| a.send self }
		end
	end
end

module Enumerable # :nodoc:
	unless [].respond_to? :group_by
		# 1.9 backport
		def group_by
			hash = Hash.new { |h, key| h[key] = [] }
			each { |item| hash[yield(item)] << item }
			hash
		end
	end

	unless [].respond_to? :sum
		def sum initial=0
			inject(initial) { |a, b| a + b }
		end
	end
end

# move to support?
class IO # :nodoc:
	# Copy data from IO-like object +src+, to +dst+
	def self.copy src, dst
		until src.eof?
			buf = src.read(4096)
			dst.write buf
		end
	end
end

class Logger # :nodoc:
	# A helper method for creating a +Logger+ which produce call stack
	# in their output
	def self.new_with_callstack logdev=STDERR
		log = Logger.new logdev
		log.level = WARN
		log.formatter = proc do |severity, time, progname, msg|
			# find where we were called from, in our code
			callstack = caller.dup
			callstack.shift while callstack.first =~ /\/logger\.rb:\d+:in/
			from = callstack.first.sub(/:in `(.*?)'/, ":\\1")
			"[%s %s]\n%-7s%s\n" % [time.strftime('%H:%M:%S'), from, severity, msg.to_s]
		end
		log
	end
end

# Include this module into a class that defines #each_child. It should
# maybe use #each instead, but its easier to be more specific, and use
# an alias.
#
# I don't want to force the class to cache children (eg where children
# are loaded on request in pst), because that forces the whole tree to
# be loaded. So, the methods should only call #each_child once, and 
# breadth first iteration holds its own copy of the children around.
#
# Main methods are #recursive, and #to_tree
module RecursivelyEnumerable # :nodoc:
	def each_recursive_depth_first(&block)
		each_child do |child|
			yield child
			if child.respond_to? :each_recursive_depth_first
				child.each_recursive_depth_first(&block)
			end
		end
	end

	# don't think this is actually a proper breadth first recursion. only first
	# level is breadth first.
	def each_recursive_breadth_first(&block)
		children = []
		each_child do |child|
			children << child if child.respond_to? :each_recursive_breadth_first
			yield child
		end
		children.each { |child| child.each_recursive_breadth_first(&block) }
	end

	def each_recursive mode=:depth_first, &block
		# we always actually yield ourself (the tree root) before recursing
		yield self
		send "each_recursive_#{mode}", &block
	end

	# the idea of this function, is to allow use of regular Enumerable methods
	# in a recursive fashion. eg:
	#
	#   # just looks at top level children
	#   root.find { |child| child.some_condition? }
	#   # recurse into all children getting non-folders, breadth first
	#   root.recursive(:breadth_first).select { |child| !child.folder? }
	#   # just get everything
	#   items = root.recursive.to_a
	#
	def recursive mode=:depth_first
		to_enum(:each_recursive, mode)
	end

	# streams a "tree" form of the recursively enumerable structure to +io+, or
	# return a string form instead if +io+ is not specified.
	#
	# mostly a debugging aid. can specify a different block which will be called
	# to provide the string form for each node.
	def to_tree io='', &inspect
		inspect ||= :inspect.to_proc
		io << "- #{inspect[self]}\n"
		recurse = proc do |node, prefix|
			child = nil
			node.each_child do |next_child|
				if child
					io << "#{prefix}|- #{inspect[child]}\n"
					recurse.call child, prefix + '|  '
				end
				child = next_child
			end if node.respond_to?(:each_child)
			if child
				io << "#{prefix}\\- #{inspect[child]}\n"
				recurse.call child, prefix + '   '
			end
		end
		recurse.call self, '  '
		io
	end
end

# can include File::Constants
class IO
	# this is for jruby
	include File::Constants unless defined?(RDONLY)

	# nabbed from rubinius, and modified
	def self.parse_mode mode
		ret = 0

		case mode[0, 1]
		when 'r'; ret |= RDONLY
		when 'w'; ret |= WRONLY | CREAT | TRUNC
		when 'a'; ret |= WRONLY | CREAT | APPEND
		else raise ArgumentError, "illegal access mode #{mode}"
		end

		(1...mode.length).each do |i|
			case mode[i, 1]
			when '+'; ret = (ret & ~(RDONLY | WRONLY)) | RDWR
			when 'b'; ret |= Mode::BINARY
			else raise ArgumentError, "illegal access mode #{mode}"
			end
		end
	
		ret
	end

	class Mode
		# ruby 1.9 defines binary as 0, which isn't very helpful.
		# its 4 in rubinius. no longer using
		#
		#   BINARY = 0x4 unless defined?(BINARY)
		#
		# for that reason, have my own constants module here
		module Constants
			include File::Constants
			BINARY = 0x4
		end
		
		include Constants
		NAMES = %w[rdonly wronly rdwr creat trunc append binary]

		attr_reader :flags
		def initialize flags
			flags = IO.parse_mode flags.to_str if flags.respond_to? :to_str
			raise ArgumentError, "invalid flags - #{flags.inspect}" unless Fixnum === flags
			@flags = flags
		end

		def writeable?
			#(@flags & RDONLY) == 0
			(@flags & 0x3) != RDONLY
		end

		def readable?
			(@flags & WRONLY) == 0
		end

		def truncate?
			(@flags & TRUNC) != 0
		end

		def append?
			(@flags & APPEND) != 0
		end

		def create?
			(@flags & CREAT) != 0
		end

		def binary?
			(@flags & BINARY) != 0
		end

=begin
		# revisit this
		def apply io
			if truncate?
				io.truncate 0
			elsif append?
				io.seek IO::SEEK_END, 0
			end
		end
=end

		def inspect
			names = NAMES.map { |name| name if (flags & Mode.const_get(name.upcase)) != 0 }
			names.unshift 'rdonly' if (flags & 0x3) == 0
			"#<#{self.class} #{names.compact * '|'}>"
		end
	end
end

