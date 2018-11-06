# A task run by Metasploit Pro.
class Mdm::Task < ActiveRecord::Base
  #
  #
  # Associations
  #
  #

  # Listeners spawned by this task
  has_many :listeners,
           class_name: 'Mdm::Listener',
           dependent: :destroy,
           inverse_of: :task

  # Joins this to {#creds}.
  has_many :task_creds,
           class_name: 'Mdm::TaskCred',
           dependent: :destroy,
           inverse_of: :task

  # Joins this to {#hosts}.
  has_many :task_hosts,
           class_name: 'Mdm::TaskHost',
           dependent: :destroy,
           inverse_of: :task

  # Joins this to {#services}.
  has_many :task_services,
           class_name: 'Mdm::TaskService',
           dependent: :destroy,
           inverse_of: :task

  # Joins this to {#sessions}.
  has_many :task_sessions,
           class_name: 'Mdm::TaskSession',
           dependent: :destroy,
           inverse_of: :task

  # The Workspace the Task belongs to
  belongs_to :workspace,
             class_name: 'Mdm::Workspace',
             inverse_of: :tasks

  #
  # through: :task_creds
  #

  # Creds this task touched
  has_many :creds, :through => :task_creds, :class_name => 'Mdm::Cred'

  #
  # through: :task_hosts
  #

  # Hosts this task touched
  has_many :hosts, :through => :task_hosts, :class_name => 'Mdm::Host'

  #
  # through: :task_services
  #

  # Services this task touched
  has_many :services, :through => :task_services, :class_name => 'Mdm::Service'

  #
  # through: :task_sessions
  #

  # Session this task touched
  has_many :sessions, :through => :task_sessions, :class_name => 'Mdm::Session'




  # @!attribute created_by
  #   {Mdm::User#username Name of user} that created this task.
  #
  #   @return [String]

  # @!attribute description
  #   Description of what the this task does.
  #
  #   @return [String]

  # @!attribute error
  #   Error raised while task was running that caused this task to fail.
  #
  #   @return [String]

  # @!attribute info
  #   Information about the task's current status.  What the task is currently doing.
  #
  #   @return [String]

  # @!attribute module
  #   {Mdm::Module::Class#full_name Module full name} that was run for this task.
  #
  #   @return [String]

  # @!attribute module_uuid
  #   UUID of `#module` that was run by this task.
  #
  #   @return [String]

  # @!attribute path
  #   Path to the log for this task.
  #
  #   @return [String]

  # @!attribute progress
  #   Percentage complete.
  #
  #   @return [Integer]

  # @!attribute updated_at
  #   When this task was last updated.
  #
  #   @return [DateTime]

  #
  # Callbacks
  #

  before_destroy :delete_file

  #
  # Serializations
  #

  # Options passed to `#module`.
  #
  # @return [Hash]
  serialize :options, MetasploitDataModels::Base64Serializer.new

  # Result of task running.
  #
  # @return [Hash]
  serialize :result, MetasploitDataModels::Base64Serializer.new

  # Settings used to configure this task outside of the {#options module options}.
  #
  # @return [Hash]
  serialize :settings, MetasploitDataModels::Base64Serializer.new

  #
  # Instance Methods
  #

  private

  # Deletes {#path log} on-disk, so that disk is cleaned up when this task is deleted from the database.
  #
  # @return [void]
  def delete_file
    c = Pro::Client.get rescue nil
    if c
      c.task_delete_log(self[:id]) if c
    else
      ::File.unlink(self.path) rescue nil
    end
  end

  # Restore public for load hooks
  public

  Metasploit::Concern.run(self)
end

