require 'singleton'

###
#
# Below are the various evasion levels.  The HIGH level indicates that the
# maximum level of evasion techniques should be used to assist in avoiding
# detection.  The rest can be inferred from there.  Typically, the higher the
# evasion level the greater the risk of failure due to increased complexity of
# tasks.
#
###
EVASION_HIGH   = "high"
EVASION_NORMAL = "normal"
EVASION_LOW    = "low"

module Rex

###
#
# Evasion
# -------
#
# This class provides a singleton interface to managing evasion levels on both
# a global level and on a per-subsystem basis.
#
###
class Evasion

	include Singleton

	@level  = EVASION_NORMAL
	@subsys = {}

	#
	# We default to a normal evasion level.  This is typically enough to be
	# sane but not enough to introduce instabilities.
	#

	#
	# Sets the global evasion level.
	#
	def self.set_level(lvl)
		@level = lvl
	end

	#
	# Returns the current global evasion level to the caller
	#
	def self.get_level
		@level
	end

	#
	# Sets the evasion level for a given subsystem
	#
	def self.set_subsys_level(subsys, lvl)
		@subsys[subsys] = lvl
	end

	#
	# Returns the evasion level for a given subsystem.  If the evasion level
	# hasn't been specified for the subsystem, the global evasion level is
	# returned.
	#
	def self.get_subsys_level(subsys)
		@subsys[subsys] || get_level
	end

	#
	# Resets the global and per-subsystem evasion levels to default.
	#
	def self.reset
		set_level(EVASION_NORMAL)
		@subsys = Hash.new
	end

	#
	# Registers the supplied subsystem so that it will show up in an
	# enumeration.
	#
	def self.register_subsys(subsys, evlvl = nil)
		@subsys[subsys] = evlvl
	end

	#
	# Removes the supplied subsystem.
	#
	def self.deregister_subsys(subsys)
		@subsys.delete(subsys)
	end

	# 
	# Returns the hash of subsystems.
	#
	def self.subsys
		@subsys
	end

end

end
