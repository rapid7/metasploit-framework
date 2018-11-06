# @deprecated {Mdm::Task} has and belongs to many `Metasploit::Credential::Cores` in `Mdm::Task#credential_cores` and
#   has and belongs to many `Metasploit::Credential::Logins` in `Mdm::Task#credential_logins` when the
#   `Metasploit::Credential::Engine` is installed.
#
# Join model between {Mdm::Cred} and {Mdm::Task} that signifies that the {#task} found the {#cred}.
class Mdm::TaskCred < ActiveRecord::Base
  #
  # Associations
  #

  # The {Mdm::Cred} found by {#task}.
  belongs_to :cred,
             class_name: 'Mdm::Cred',
             inverse_of: :task_creds

  # An {Mdm::Task} that found {#cred}.
  belongs_to :task,
             class_name: 'Mdm::Task',
             inverse_of: :task_creds

  #
  # Attributes
  #

  # @!attribute [rw] created_at
  #   When this task cred was created.
  #
  #   @return [DateTime]

  # @!attribute [rw] updated_at
  #   The last time this task cred was updated.
  #
  #   @return [DateTime]

  #
  # Validations
  #

  validates :cred_id,
            :uniqueness => {
                :scope => :task_id
            }

  Metasploit::Concern.run(self)
end
