# Records framework events to the database.
class Mdm::Event < ActiveRecord::Base
    
  #
  # Associations
  #

  # Host on which this event occurred.
  #
  # @return [Mdm::Host]
  # @return [nil] if event did not occur on a host.
  belongs_to :host,
             class_name: 'Mdm::Host',
             inverse_of: :events

  # {Mdm::Workspace} in which this event occured.  If {#host} is present, then this will match
  # {Mdm::Host#workspace `host.workspace`}.
  belongs_to :workspace,
             class_name: 'Mdm::Workspace',
             inverse_of: :events
  
  #
  # Attributes
  #

  # @!attribute created_at
  #   When this event was created.
  #
  #   @return [DateTime]

  # @!attribute critical
  #   Indicates if the event is critical.
  #
  #   @return [false] event is not critical.
  #   @return [true] event is critical.

  # @!attribute  name
  #   Name of the event, such as 'module_run'.
  #
  #   @return [String]

  # @!attribute seen
  #   Whether a user has seen these events.
  #
  #   @return [false] if the event has not been seen.
  #   @return [true] if any user has seen the event.

  # @!attribute  updated_at
  #   The last time this event was updated.
  #
  #   @return [DateTime]

  # @!attribute username
  #   Name of user that triggered the event.  Not necessarily a {Mdm::User#username}, as {#username} may be set to
  #   the username of the user inferred from `ENV` when using metasploit-framework.
  #
  #   @return [String]

  #
  # Scopes
  #

  scope :flagged, -> { where(:critical => true, :seen => false) }
  scope :module_run, -> { where(:name => 'module_run') }

  #
  # Serializations
  #

  # {#name}-specific information about this event.
  #
  # @return [Hash]
  serialize :info, MetasploitDataModels::Base64Serializer.new

  #
  # Validations
  #

  validates :name, :presence => true

  Metasploit::Concern.run(self)
end

