#!/usr/bin/env ruby
# Copyright (C) 2007 Sylvain SARMEJEANNE

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2.

# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details. 


#
# Tons of hacking/reorganization by hdm[at]metasploit.com
# All bugs are mine, not Sylvain's
#


# This is part of the core distribution.
require 'ipaddr'

require 'scruby/deps'
require 'scruby/conf'
require 'scruby/const'
require 'scruby/layer'
require 'scruby/packet'
require 'scruby/field'
require 'scruby/dissector'
require 'scruby/func'
require 'scruby/help'

module Scruby

	# This is used to allow creating objects without using "new",
	# e.g. p=IP() instead of p=IP.new()
	def self.method_missing(method, *args)

		# Looking for the field corresponding to 'method'
		dis = Scruby.get_dissector(method.to_s)

		# If no dissector was found
		raise NameError, "undefined local variable or method `#{method}' for #{self} #{caller}" if not dis

		# If a string was passed, let's try to dissect it as a Packet
		if args[0].is_a?(String)
			return Packet.new(args[0], method.to_s)

		# Otherwise, instantiating the class with arguments if supplied
		else
			 dis.new(*args)
		end
	end
	
	# Same as above, for fields
	def self.field(method, *args)

		# Looking for the field corresponding to 'method'
		field = Scruby.get_field(method.to_s)
		
		# If no field was found
		raise NameError, "undefined local variable or method `#{method}' for #{self}" if not field
		
		# Instantiating the class with arguments if supplied
		field.new(*args)
	end

	def field(method, *args)
		Scruby.field(method, *args)
	end

	def self.function_list
		(self.methods - Object.methods)
	end
	
	def function_list
		Scruby.function_list
	end
	
	attr_accessor :conf
	
	def initialize(*args)
		super(*args)
		@conf = Conf.new
	end

end

class ScrubyBasic
	include Scruby
end

# If we were not called from a module, let's spawn a shell.
if (__FILE__ == $0)


	shell = ScrubyBasic.new
	
	# This is part of the core distribution.
	begin
		require 'readline'
	rescue ::LoadError
		puts 'FATAL: module Readline not found.'
		exit
	end

	# Welcome :)
	
	puts "Welcome to Scruby (#{Scruby::SCRUBY_VERSION}) Copyright 2007 Sylvain SARMEJEANNE"
	puts "This version has been mangled by hdm[at]metasploit.com"
	puts "Blame all bugs on HD :-)"
	puts ""
	puts 'If you\'re lost, just shout for "help".'

	# Setting the terminal
	prompt = 'scruby> '

	Readline.completion_proc =
		proc {|word| (Scruby.function_list + Scruby.dissectors.keys).grep(/\A#{Regexp.quote word}/)}

	# Main loop
	begin
		line = Readline.readline(prompt, Scruby::RECORD_HISTORY)
		begin
			puts(shell.instance_eval(line)) if line != nil
		rescue SystemExit => e
			raise e			
		rescue Exception => e
			puts "#{e.class}: #{e} #{e.backtrace}"
		end
	end until line == nil
	puts
end