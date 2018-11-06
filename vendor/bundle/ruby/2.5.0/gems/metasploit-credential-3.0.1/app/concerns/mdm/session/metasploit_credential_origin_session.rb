# Add `credential_origins` association to `Mdm::Session`.
module Mdm::Session::MetasploitCredentialOriginSession
  extend ActiveSupport::Concern

  included do
    #
    # Associations
    #

    # @!attribute credential_origins
    #   The {Metasploit::Credential::Origin::Session credential origins} from this session.
    #
    #   @return [ActiveRecord::Relation<Metasploit::Credential::Origin::Session>]
    has_many :credential_origins,
             class_name: 'Metasploit::Credential::Origin::Session',
             dependent: :destroy,
             inverse_of: :session
  end
end