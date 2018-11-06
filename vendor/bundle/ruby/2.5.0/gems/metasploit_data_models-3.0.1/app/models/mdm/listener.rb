# A listener spawned by a {#task} that is waiting for connection on {#address}:{#port}.
class Mdm::Listener < ActiveRecord::Base
  
  #
  # Associations
  #

  # Task that spawned this listener.
  belongs_to :task,
             class_name: 'Mdm::Task',
             inverse_of: :listeners

  # Workspace which controls this listener.
  belongs_to :workspace,
             class_name: 'Mdm::Workspace',
             inverse_of: :listeners

  #
  # Attributes
  #

  # @!attribute address
  #   The IP address to which the listener is bound.
  #
  #   @return [String]

  # @!attribute created_at
  #   When this listener was created.  Not necessarily when it started listening.
  #
  #   @return [DateTime]

  # @!attribute enabled
  #   Whether listener is listening on {#address}:{#port}.
  #
  #   @return [true] listener is listening.
  #   @return [false] listener is not listening.

  # @!attribute macro
  #   {Mdm::Macro#name Name of macro} run when a connect is made to the listener.
  #
  #   @return [String]

  # @!attribute owner
  #   The name of the user that setup this listener.
  #
  #   @return [String]
  #   @see Mdm::User#username

  # @!attribute payload
  #   Reference name of the payload module that is sent when a connection is made to the listener.
  #
  #   @return [String]

  # @!attribute port
  #   Port on {#address} that listener is listening.
  #
  #   @return [Integer]

  # @!attribute updated_at
  #   The last time this listener was updated.
  #
  #   @return [DateTime]

  #
  # Serializations
  #

  # Options used to spawn this listener.
  #
  # @return [Hash]
  serialize :options, MetasploitDataModels::Base64Serializer.new

  #
  # Validations
  #

  validates :address, :ip_format => true, :presence => true
  validates :port, :presence => true, :numericality => { :only_integer => true }, :inclusion => {:in => 1..65535}

  Metasploit::Concern.run(self)
end

