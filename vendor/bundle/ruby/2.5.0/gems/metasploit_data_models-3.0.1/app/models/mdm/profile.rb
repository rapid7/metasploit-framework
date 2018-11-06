# User settings.
class Mdm::Profile < ActiveRecord::Base
  #
  # Attributes
  #

  # @!attribute active
  #   Whether this is the currently active profile.
  #
  #   @return [true] if this is the active profile.
  #   @return [false] if this profile is inactive and another profile is active.

  # @!attribute created_at
  #   When this profile was created.
  #
  #   @return [DateTime]

  # @!attribute name
  #   Name of this profile to distinguish it from other profiles.
  #
  #   @return [String]

  # @!attribute owner
  #   Owner of this profile.
  #
  #   @return ['<system>'] System-wide profile for all users.
  #   @return [String] Name of user that uses this profile.

  # @!attribute updated_at
  #   The last time this profile was updated.
  #
  #   @return [DateTime]

  #
  # Serializations
  #

  # Global settings.
  #
  # @return [Hash]
  serialize :settings, MetasploitDataModels::Base64Serializer.new

  Metasploit::Concern.run(self)
end

