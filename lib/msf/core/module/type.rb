module Msf::Module::Type
  extend ActiveSupport::Concern

  module ClassMethods
    #
    # Class method to figure out what type of module this is
    #
    def type
      raise NotImplementedError
    end
  end

  #
  # Instance Methods
  #

  #
  # Returns true if this module is an auxiliary module.
  #
  def auxiliary?
    (type == Msf::MODULE_AUX)
  end

  #
  # Returns true if this module is an encoder module.
  #
  def encoder?
    (type == Msf::MODULE_ENCODER)
  end

  #
  # Returns true if this module is an exploit module.
  #
  def exploit?
    (type == Msf::MODULE_EXPLOIT)
  end

  #
  # Returns true if this module is a nop module.
  #
  def nop?
    (type == Msf::MODULE_NOP)
  end

  #
  # Returns true if this module is a payload module.
  #
  def payload?
    (type == Msf::MODULE_PAYLOAD)
  end

  #
  # Returns true if this module is an post-exploitation module.
  #
  def post?
    (type == Msf::MODULE_POST)
  end

  def evasion?
    (type == Msf::MODULE_EVASION)
  end

  #
  # Return the module's abstract type.
  #
  def type
    raise NotImplementedError
  end
end