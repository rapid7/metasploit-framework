# NOTE: Metasploit does not use real UUIDs currently.
# To modify this to be a real UUID we will need to do a database migration.
# See: https://github.com/rapid7/metasploit-framework/pull/20170
module Msf::Module::UUID
  UUID_CHARS = [*('a'..'z'), *('0'..'9')].freeze
  private_constant :UUID_CHARS

  #
  # Attributes
  #

  # @return [String] A unique identifier for this module instance
  def uuid
    @uuid ||= UUID_CHARS.sample(8).join
  end

  protected

  #
  # Attributes
  #

  # @!attribute [w] uuid
  attr_writer :uuid
end
