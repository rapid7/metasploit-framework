# Join model between {Mdm::Session} and {Mdm::Task} that signifies that the {#task} spawned the {#session}.
class Mdm::TaskSession < ActiveRecord::Base
  #
  # Associations
  #

  # The {Mdm::Session} found by {#task}.
  belongs_to :session,
             class_name: 'Mdm::Session',
             inverse_of: :task_sessions

  # An {Mdm::Task} that found {#session}
  belongs_to :task,
             class_name: 'Mdm::Task',
             inverse_of: :task_sessions

  #
  # Attributes
  #

  # @!attribute created_at
  #   When this task session was created.
  #
  #   @return [DateTime]

  # @!attribute updated_at
  #   The last time this task session was updated.
  #
  #   @return [DateTime]

  #
  # Validations
  #

  validates :session_id,
            :uniqueness => {
                :scope => :task_id
            }

  Metasploit::Concern.run(self)
end
