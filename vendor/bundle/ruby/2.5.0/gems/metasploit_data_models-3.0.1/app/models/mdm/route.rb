# Network route that goes through a {#session} to allow accessing IPs on the remote end of the session.
class Mdm::Route < ActiveRecord::Base
  
  #
  # Associations
  #

  # The session over which this route traverses.
  belongs_to :session,
             class_name: 'Mdm::Session',
             inverse_of: :routes

  #
  # Attributes
  #

  # @!attribute netmask
  #   The netmask for this route.
  #
  #   @return [String]

  # @!attribute subnet
  #   The subnet for this route.
  #
  #   @return [String]

  Metasploit::Concern.run(self)
end
