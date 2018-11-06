# Client used for `report_client` in metasploit-framework Metasploit Modules.
class Mdm::Client < ActiveRecord::Base
  #
  # Associations
  #

  # {Mdm::Host} from which this client connected.
  belongs_to :host,
             class_name: 'Mdm::Host',
             inverse_of: :clients

  #
  # Attributes
  #

  # @!attribute created_at
  #   When this client was created.
  #
  #   @return [DateTime]

  # @!attribute updated_at
  #   When this client was last updated.
  #
  #   @return [DateTime]

  #
  # @!group User Agent
  #

  # @!attribute ua_name
  #   Parsed name from {#ua_string user agent string}
  #
  #   @return [String]

  # @!attribute ua_string
  #   Raw user agent string from client browser
  #
  #   @return [String]

  # @!attribute ua_ver
  #   Version of user agent.
  #
  #   @return [String]

  #
  # @!endgroup
  #

  Metasploit::Concern.run(self)
end
