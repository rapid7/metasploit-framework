module Msf::Module::Privileged
  #
  # Attributes
  #

  # @!attribute [r] privileged
  #   Whether or not this module requires privileged access.
  attr_reader   :privileged

  #
  # Instance Methods
  #

  #
  # Returns whether or not the module requires or grants high privileges.
  #
  def privileged?
    privileged == true
  end

  protected

  #
  # Attributes
  #

  # @!attribute [w] privileged
  attr_writer :priveli
end