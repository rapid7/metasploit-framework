# Add `import_credential_origins` association to `Mdm::Task`.
module Mdm::Task::MetasploitCredentialOriginImport
  extend ActiveSupport::Concern

  included do
    #
    # Associations
    #

    # @!attribute import_credential_origins
    #   The {Metasploit::Credential::Origin::Import credential origins} from this import task.
    #
    #   @return [ActiveRecord::Relation<Metasploit::Credential::Origin::Import>]
    has_many :import_credential_origins,
             class_name: 'Metasploit::Credential::Origin::Import',
             dependent: :destroy,
             inverse_of: :task
  end
end