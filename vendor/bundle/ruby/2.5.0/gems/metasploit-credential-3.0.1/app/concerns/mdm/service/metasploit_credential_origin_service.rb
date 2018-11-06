# Add `credential_origins` association to `Mdm::Service`.
module Mdm::Service::MetasploitCredentialOriginService
  extend ActiveSupport::Concern

  included do
    #
    # Associations
    #

    # @!attribute credential_origins
    #   The {Metasploit::Credential::Origin::Service credential origins} from this service.
    #
    #   @return [ActiveRecord::Relation<Metasploit::Credential::Origin::Service>]
    has_many :credential_origins,
             class_name: 'Metasploit::Credential::Origin::Service',
             dependent: :destroy,
             inverse_of: :service
  end
end
