# Request sent to a {Mdm::WmapTarget}.  WMAP is a plugin to metasploit-framework.
class Mdm::WmapRequest < ActiveRecord::Base
  #
  #
  # Attributes
  #
  #

  # @!attribute address
  #   IP address of {#host} to which this request was sent.
  #
  #   @return [String]

  # @!attribute body
  #   Body of this request.
  #
  #   @return [String]

  # @!attribute created_at
  #   When this request was created.
  #
  #   @return [DateTime]

  # @!attribute headers
  #   Headers sent as part of this request.
  #
  #   @return [String]

  # @!attribute host
  #   Name of host to which this request was sent.
  #
  #   @return [String]

  # @!attribute meth
  #   HTTP Method (or VERB) used for request.
  #
  #   @return [String]

  # @!attribute path
  #   Path portion of URL for this request.
  #
  #   @return [String]

  # @!attribute port
  #   Port at {#address} to which this request was sent.
  #
  #   @return [Integer]

  # @!attribute query
  #   Query portion of URL for this request.
  #
  #   @return [String]

  # @!attribute ssl
  #   Version of SSL to use.
  #
  #   @return [Integer]

  # @!attribute updated_at
  #   The last time this request was updated.
  #
  #   @return [DateTime]

  #
  # @!group Response
  #

  # @!attribute respcode
  #   HTTP status code sent in response to this request from server.
  #
  #   @return [String]

  # @!attribute resphead
  #   Headers sent in response from server.
  #
  #   @return [String]

  # @!attribute response
  #   Response sent from server.
  #
  #   @return [String]

  #
  # @!endgroup
  #

  #
  # Instance Methods
  #

  # @note Necessary to avoid coercion to an `IPAddr` object.
  #
  # The IP address for this request.
  #
  # @return [String]
  def address
    self[:address].to_s
  end

  Metasploit::Concern.run(self)
end
