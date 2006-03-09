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
	require 'msf/core/auxiliary/tcp'

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
	# Creates an instance of the exploit module.  Mad skillz.
	#
	def initialize(info = {})

		# Call the parent constructor after making any necessary modifications
		# to the information hash.
		super(info)

		self.actions = Rex::Transformer.transform(
			info['Actions'], Array,
			[ AuxiliaryAction ], 'AuxiliaryAction'
		)
		
		self.default_action = info['DefaultAction']
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
	# Allow access to the hash table of actions and the string containing
	# the default action
	# 
	attr_reader :actions, :default_action
	
protected
	
	attr_writer :actions, :default_action

end

end
