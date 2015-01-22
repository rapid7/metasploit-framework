module Msf::Module::UUID
  #
  # Attributes
  #

  # @!attribute [r] uuid
  #   A unique identifier for this module instance
  attr_reader :uuid

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