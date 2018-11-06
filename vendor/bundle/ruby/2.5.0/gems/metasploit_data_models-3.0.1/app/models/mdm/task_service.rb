# Join model between {Mdm::Service} and {Mdm::Task} that signifies that the {#task} found the {#service}.
class Mdm::TaskService < ActiveRecord::Base
  #
  # Associations
  #

  # The {Mdm::Service} found by {#task}.
  belongs_to :service,
             class_name: 'Mdm::Service',
             inverse_of: :task_services

  # An {Mdm::Task} that found {#service}.
  belongs_to :task,
             class_name: 'Mdm::Task',
             inverse_of: :task_services

  #
  # Attributes
  #

  # @!attribute created_at
  #   When this task service was created.
  #
  #   @return [DateTime]

  # @!attribute updated_at
  #   The last time this task service was updated.
  #
  #   @return [DateTime]

  #
  # Validations
  #

  validates :service_id,
            :uniqueness => {
                :scope => :task_id
            }

  Metasploit::Concern.run(self)
end
