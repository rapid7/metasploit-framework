# Add `logins` association to `Mdm::Service`.
module Mdm::Service::MetasploitCredentialLogin
  extend ActiveSupport::Concern

  included do
    #
    # Associations
    #

    # @!attribute logins
    #   The {Metasploit::Credential::Login logins} to this service.
    #
    #   @return [ActiveRecord::Relation<Metasploit::Credential::Login>]
    has_many :logins,
             class_name: 'Metasploit::Credential::Login',
             dependent: :destroy,
             inverse_of: :service
  end
end
