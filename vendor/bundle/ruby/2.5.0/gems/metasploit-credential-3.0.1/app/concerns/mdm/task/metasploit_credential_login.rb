# Add `credential_cores` association to `Mdm::Task`.
module Mdm::Task::MetasploitCredentialLogin
  extend ActiveSupport::Concern

  included do
    #
    # Associations
    #

    # @!attribute credential_cores
    #   The {Metasploit::Credential::Core credential origins} from this import task.
    #
    #   @return [ActiveRecord::Relation<Metasploit::Credential::Core>]
    has_and_belongs_to_many :credential_logins, 
                            -> { uniq },
                            class_name: "Metasploit::Credential::Login", 
                            join_table: "credential_logins_tasks"
  end
end