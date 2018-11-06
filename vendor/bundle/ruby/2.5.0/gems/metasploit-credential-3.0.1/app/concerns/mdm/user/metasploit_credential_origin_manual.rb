# Add `credential_origins` to `Mdm::User`
module Mdm::User::MetasploitCredentialOriginManual
  extend ActiveSupport::Concern

  included do
    #
    # Associations
    #

    # @!attribute credential_origins
    #   The {Metasploit::Credential::Origin::Manual credential origins} entered by this user.
    #
    #   @return [ActiveRecord::Relation<Metasploit::Credential::Origin::Manual>]
    has_many :credential_origins,
             class_name: 'Metasploit::Credential::Origin::Manual',
             dependent: :destroy,
             inverse_of: :user
  end
end