# Join model between {Mdm::Host} and {Mdm::Task} that signifies that the {#task} found the {#host}.
class Mdm::TaskHost < ActiveRecord::Base
  #
  # Associations
  #

  # The {Mdm::Host} found by {#task}.
  belongs_to :host,
             class_name: 'Mdm::Host',
             inverse_of: :task_hosts

  # An {Mdm::Task} that found {#host}.
  belongs_to :task,
             class_name: 'Mdm::Task',
             inverse_of: :task_hosts

  #
  # Attributes
  #

  # @!attribute created_at
  #   When this task host was created.
  #
  #   @return [DateTime]

  # @!attribute updated_at
  #   The last time this task host was updated.
  #
  #   @return [DateTime]

  #
  # Validations
  #

  validates :host_id,
            :uniqueness => {
                :scope => :task_id
            }

  Metasploit::Concern.run(self)
end
