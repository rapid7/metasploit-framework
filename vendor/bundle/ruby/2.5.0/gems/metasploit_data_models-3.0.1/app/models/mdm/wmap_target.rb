# WMAP target. WMAP is a plugin to metasploit-framework.
class Mdm::WmapTarget < ActiveRecord::Base
  #
  # Attributes
  #

  # @!attribute address
  #   IP address of {#host}.
  #
  #   @return [String]

  # @!attribute created_at
  #   When this target was created.
  #
  #   @return [DateTime]

  # @!attribute host
  #   Name of this target.
  #
  #   @return [String]

  # @!attribute port
  #   Port on this target to send {Mdm::WmapRequest requests}.
  #
  #   @return [Integer]

  # @!attribute selected
  #   Whether this target should be sent requests.
  #
  #   @return [Integer]

  # @!attribute ssl
  #   Version of SSL to use when sending requests to this target.
  #
  #   @return [Integer]

  # @!attribute updated_at
  #   The last time this target was updated.
  #
  #   @return [DateTime]

  #
  # Instance Methods
  #

  # @note Necessary to avoid coercion to an `IPAddr` object.
  #
  # The IP address for this target.
  #
  # @return [String]
  def address
    self[:address].to_s
  end

  Metasploit::Concern.run(self)
end
