# Add `credential_cores` association to `Mdm::Task`.
module Mdm::Task::MetasploitCredentialCore
  extend ActiveSupport::Concern

  included do
    #
    # Associations
    #

    # @!attribute credential_cores
    #   The {Metasploit::Credential::Core credential origins} from this import task.
    #
    #   @return [ActiveRecord::Relation<Metasploit::Credential::Core>]
    has_and_belongs_to_many :credential_cores, 
                            -> { uniq },
                            class_name: "Metasploit::Credential::Core", 
                            join_table: "credential_cores_tasks"
  end
end