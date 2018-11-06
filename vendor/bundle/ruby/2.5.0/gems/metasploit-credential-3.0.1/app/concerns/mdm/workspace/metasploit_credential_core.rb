# Add `credential_cores` to `Mdm::Workspace`
module Mdm::Workspace::MetasploitCredentialCore
  extend ActiveSupport::Concern

  included do
    #
    # Associations
    #

    # @!attribute credential_cores
    #   The {Metasploit::Credential::Core credential cores} restricted to this workspace.
    #
    #   @return [ActiveRecord::Relation<Metasploit::Credential::Corel>]
    has_many :core_credentials,
             class_name: 'Metasploit::Credential::Core',
             dependent: :destroy,
             inverse_of: :workspace

  end
end