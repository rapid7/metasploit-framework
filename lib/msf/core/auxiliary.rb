require 'msf/core/module'

module Msf

###
#
# The auxiliary class acts as a base class for all modules that perform
# reconnaisance, retrieve data, brute force logins, or any other action
# that doesn't fit our concept of an 'exploit' (involving payloads and 
# targets and whatnot).
#
###
class Auxiliary < Msf::Module

	#
	# Auxiliary mixins
	#
	require 'msf/core/auxiliary/scanner'
	require 'msf/core/auxiliary/report'
	require 'msf/core/auxiliary/dos'
	require 'msf/core/auxiliary/timed'
	require 'msf/core/auxiliary/wmapmodule'
	
	#
	# Returns MODULE_AUX to indicate that this is an auxiliary module.
	#
	def self.type
		MODULE_AUX
	end

	#
	# Returns MODULE_AUX to indicate that this is an auxiliary module.
	#
	def type
		MODULE_AUX
	end
	
	#
	# Creates an instance of the auxiliary module. 
	#
	def initialize(info = {})

		# Call the parent constructor after making any necessary modifications
		# to the information hash.
		super(info)

		self.actions = Rex::Transformer.transform(
			info['Actions'], Array,
			[ AuxiliaryAction ], 'AuxiliaryAction'
		)
		
		self.passive = (info['Passive'] and info['Passive'] == true) || false
		self.default_action = info['DefaultAction']
		self.sockets = Array.new
		self.queue   = Array.new
		self.passive_actions = info['PassiveActions'] || []
	end
	
	#
	# Creates a singleton instance of this auxiliary class
	#
	def self.create(info = {})
		return @@aux_singleton if @@aux_singleton
		@@aux_singleton = self.new(info)
	end
	
	def run
		print_status("Running the default Auxiliary handler")
	end

	def auxiliary_commands
		return { }
	end

	def action
		sa = datastore['ACTION']
		return find_action(default_action) if not sa
		return find_action(sa)
	end

	def find_action(name)
		return nil if not name
		actions.each do |a|
			return a if a.name == name
		end
		return nil
	end
	
	#
	# Returns a boolean indicating whether this module should be run passively
	#
	def passive?
		act = action()
		return passive_action?(act.name) if act
		return self.passive
	end
	
	#
	# Returns a boolean indicating whether this specific action should be run passively
	#
	def passive_action?(name)
		passive_actions.include?(name)
	end

	#
	# Performs last-minute sanity checking of auxiliary parameters. This method
	# is called during automated exploitation attempts and allows an
	# auxiliary module to filter bad attempts, obtain more information, and choose
	# better parameters based on the available data. Returning anything that
	# evaluates to "false" will cause this specific auxiliary attempt to
	# be skipped. This method can and will change datastore values and
	# may interact with the backend database. The default value for auxiliary
	# modules is false, since not all auxiliary modules actually attempt
	# to exploit a vulnerability.
	#
	def autofilter
		false
	end
		
	#
	# Called directly before 'run'
	#
	def setup
	end
	
	#
	# Called after 'run' returns
	#
	def cleanup
		abort_sockets()
	end
	
	#
	# Adds a socket to the list of sockets opened by this exploit.
	#
	def add_socket(sock)
		self.sockets << sock
	end

	#
	# Removes a socket from the list of sockets.
	#
	def remove_socket(sock)
		self.sockets.delete(sock)
	end

	#
	# This method is called once a new session has been created on behalf of
	# this module instance and all socket connections created by this
	# module should be closed.
	#
	def abort_sockets
		sockets.delete_if { |sock|
			if (sock.respond_to?('abortive_close'))
				sock.abortive_close = true 
			end
			begin
				disconnect(sock)
			rescue
			end

			true
		}
	end
		
	# 
	# Allow access to the hash table of actions and the string containing
	# the default action
	# 
	attr_reader :actions, :default_action, :passive, :passive_actions
	attr_accessor :queue
	
protected
	
	attr_writer :actions, :default_action
	attr_accessor :sockets
	attr_writer :passive, :passive_actions
	

end

end