# -*- coding: binary -*-
module Rex
module Poly

###
#
# This class represents a register that is used in the context of one or more
# logical blocks.  The register number is assigned on demand or is statically
# specified if passed in to the constructor.
#
###
class LogicalRegister

  require 'rex/poly/register/x86'

  #
  # This class method is meant to return an array of register numbers that
  # can be used to pool from.  Architecture specific classes must implement
  # this method on their own.
  #
  def self.regnum_set
    nil
  end

  #
  # Initializes the register's name and number, if assigned.  If a register
  # number is specified, the instance will be assumed to have a statically
  # assigned register number.  The name is meant to be used as a symbolic
  # variable name, such as 'counter' or 'key'.
  #
  def initialize(name, regnum = nil)
    @name   = name
    @regnum = regnum
    @static = (regnum) ? true : false
  end

  #
  # Returns true if the register number should be assumed static.
  #
  def static?
    @static
  end

  #
  # Sets the register number to the value specified.  If the register number
  # is declared static, a RuntimeError exception is raised.
  #
  def regnum=(val)
    raise RuntimeError, "Attempted to assign regnum to static register" if (static?)

    @regnum = val
  end

  #
  # Returns the register number that has currently been assigned.  If no
  # register number is assigned, an InvalidRegisterError exception is raised.
  # This exception can be used to assign the LogicalRegister instance a
  # register number on demand.
  #
  def regnum
    raise InvalidRegisterError.new(self), "Register has not been assigned" if (@regnum == nil)

    @regnum
  end

  #
  # Returns the variable (friendly) name for the register that was passed to
  # the constructor.
  #
  attr_reader :name

protected

end

###
#
# An exception that is raised when the regnum method is accessed on a
# LogicalRegister that does not currently have a regnum assigned to it.
#
###
class InvalidRegisterError < RuntimeError

  #
  # Initializes the exception with the instance that lead to the generation
  # of the exception such that it can be assigned a register number as
  # needed.
  #
  def initialize(reg)
    @reg = reg
  end

  #
  # The LogicalRegister instance that generated the exception.
  #
  attr_reader :reg

end

end
end
