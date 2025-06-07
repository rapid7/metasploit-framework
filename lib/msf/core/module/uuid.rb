require 'rex/text'

module Msf::Module::UUID
  #
  # Attributes
  #

  # @return [String] A unique identifier for this module instance
  def uuid
    @uuid ||= generate_uuid
  end

  protected

  #
  # Attributes
  #

  # @!attribute [w] uuid
  attr_writer :uuid


  #
  # Instance Methods
  #

  def generate_uuid
    self.uuid = Rex::Text.rand_text_alphanumeric(8).downcase
  end
end
