# A session opened on a {#host} using an {#via_exploit exploit} and controlled through a {#via_payload payload} to
# connect back to the local host using meterpreter or a cmd shell.
class Mdm::Session < ActiveRecord::Base
  
  #
  # Associations
  #

  # @!attribute [rw] events
  #   Events that occurred when this session was open.
  #
  #   @return [Array<Mdm::Event>]
  has_many :events,
            -> { order('created_at') },
            class_name: 'Mdm::SessionEvent',
            dependent: :delete_all,
            inverse_of: :session

  # @!attribute exploit_attempt
  #   Exploit attempt that created this session.
  #
  #   @return [Mdm::ExploitAttempt]
  has_one :exploit_attempt,
          class_name: 'Mdm::ExploitAttempt',
          inverse_of: :session

  # @!attribute [rw] host
  #   {Mdm::Host Host} on which this session was opened.
  #
  #   @return [Mdm::Host]
  belongs_to :host,
             class_name: 'Mdm::Host',
             inverse_of: :sessions

  # @!attribute [rw] routes
  #   Routes tunneled throug this session.
  #
  #   @return [ActiveRecord::Relation<Mdm::Route>]
  has_many :routes,
           class_name: 'Mdm::Route',
           dependent: :delete_all,
           inverse_of: :session

  # @!attribute [rw] originating_module_run
  #   Records the Metasploit modules run that created this session
  #
  #   @return [MetasploitDataModels::ModuleRun]
  belongs_to :originating_module_run,
           class_name: 'MetasploitDataModels::ModuleRun',
           foreign_key: :module_run_id,
           inverse_of: :spawned_session

  # @!attribute [rw] target_module_runs
  #   Records the Metasploit modules run on this session
  #
  #   @return [ActiveRecord::Relation<MetasploitDataModels::ModuleRun>]
  has_many :target_module_runs,
           class_name: 'MetasploitDataModels::ModuleRun',
           inverse_of: :target_session

  # @!attribute vuln_attempt
  #   Vulnerability attempt that created this session.
  #
  #   @return [Mdm::VulnAttempt]
  has_one :vuln_attempt,
          class_name: 'Mdm::VulnAttempt',
          inverse_of: :session

  #
  # Through :host
  #

  # @!attribute [r] workspace
  #   The workspace in which this session exists.
  #
  #   @return [Mdm::Workspace]
  has_one :workspace, :through => :host, :class_name => 'Mdm::Workspace'

  # @!attribute [rw] task_sessions
  #   Details about sessions this task touched
  #
  #   @return [Array<Mdm::TaskSession>]
  has_many :task_sessions, :dependent => :destroy, :class_name => 'Mdm::TaskSession'

  # @!attribute [rw] task
  #   Session this task touched
  #
  #   @return [Mdm::Session]
  has_many :tasks, :through => :task_sessions, :class_name => 'Mdm::Task'

  #
  # Attributes
  #

  # @!attribute [rw] closed_at
  #   When the session was closed on {#host}.
  #
  #   @return [DateTime]

  # @!attribute [rw] close_reason
  #   Why the session was closed.  Used to differentiate between user killing it local and the session being killed on
  #   the remote end.
  #
  #   @return [String]

  # @!attribute [rw] datastore
  #   Options for {#via_exploit exploit} and {#via_payload} modules.
  #
  #   @return [Hash]

  # @!attribute [rw] desc
  #   Description of session.
  #
  #   @return [String]

  # @!attribute [rw] last_seen
  #   The last time the session was checked to see that it was still open.
  #
  #   @return [DateTime]

  # @!attribute [rw] local_id
  #   The ID number of the in-memory session.
  #
  #   @return [Integer]

  # @!attribute [rw] opened_at
  #   When the session was opened on {#host}.
  #
  #   @return [DateTime]

  # @!attribute [rw] platform
  #   The {#host} platform.
  #
  #   @return [String]

  # @!attribute [rw] port
  #   The remote port on which this session is running on {#host}.
  #
  #   @return [Integer]

  # @!attribute [rw] stype
  #   The type of the session.
  #
  #   @return [String]

  # @!attribute [rw] via_exploit
  #   The {Mdm::Module::Detail#fullname full name} of the exploit module that opened this session.
  #
  #   @return [String]

  # @!attribute [rw] via_payload
  #   The {Mdm::Module::Detail#fullname full name} if the payload module that's running this session.
  #
  #   @return [String]

  #
  # Callbacks
  #

  before_destroy :stop

  #
  # Scopes
  #

  scope :alive, -> { where('closed_at IS NULL') }
  scope :dead, -> { where('closed_at IS NOT NULL') }
  scope :upgradeable, -> { where("closed_at IS NULL AND stype = 'shell' and platform ILIKE '%win%'") }

  #
  # Serializations
  #

  serialize :datastore, ::MetasploitDataModels::Base64Serializer.new

  # Returns whether the session can be upgraded to a meterpreter session from a shell session on Windows.
  #
  # @return [true] if {#platform} is some version of Windows and {#stype} is `'shell'`.
  # @return [false] otherwise.
  def upgradeable?
    if (self.platform =~ /win/i and self.stype == 'shell')
      return true
    else
      return false
    end
  end

  private

  # Stops and closes the session.
  #
  # @todo https://www.pivotaltracker.com/story/show/49026497
  # @return [void]
  def stop
    c = Pro::Client.get rescue nil
    # ignore exceptions (XXX - ideally, stopped an already-stopped session wouldn't throw XMLRPCException)
    c.session_stop(self.local_id) rescue nil
  end

  public

  Metasploit::Concern.run(self)
end
