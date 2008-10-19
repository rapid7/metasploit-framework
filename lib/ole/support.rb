#! /usr/bin/ruby

# 
# A file with general support functions used by most files in the project.
# 

require 'logger'

class File # :nodoc:
	# for consistency with StringIO and others. makes more sense than forcing
	# them to provide a #stat
	def size
		stat.size
	end
end

class Symbol # :nodoc:
	def to_proc
		proc { |a| a.send self }
	end
end

module Enumerable # :nodoc:
	# 1.9 backport
	def group_by
		hash = Hash.new { |hash, key| hash[key] = [] }
		each { |item| hash[yield(item)] << item }
		hash
	end

	def sum initial=0
		inject(initial) { |a, b| a + b }
	end
end

class Logger # :nodoc:
	# A helper method for creating <tt>Logger</tt>s which produce call stack
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