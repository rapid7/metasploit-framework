# Loot gathered from {#host} or {#service} such as files to prove you were on the system or to crack later to gain
# sessions on other machines in the network.
class Mdm::Loot < ActiveRecord::Base
  
  #
  # CONSTANTS
  #

  RELATIVE_SEARCH_FIELDS = [
      'ltype',
      'name',
      'info',
      'data'
  ]

  #
  # Associations
  #

  # @!attribute exploit_attempt
  #   Exploit attempt where this loot was gathered.
  #
  #   @return [Mdm::ExploitAttempt]
  has_one :exploit_attempt,
          class_name: 'Mdm::ExploitAttempt',
          inverse_of: :loot

  # @!attribute [rw] host
  #   The host from which the loot was gathered.
  #
  #   @return [Mdm::Host]
  belongs_to :host,
             class_name: 'Mdm::Host',
             inverse_of: :loots

  # @!attribute [rw] module_run
  #   The run of Metasploit content that acquired the loot
  #
  #   @return [MetasploitDataModels::ModuleRun]
  belongs_to :module_run,
             class_name: 'MetasploitDataModels::ModuleRun',
             foreign_key: :module_run_id,
             inverse_of: :loots

  # @!attribute [rw] service
  #   The service running on the {#host} from which the loot was gathered.
  #
  #   @return [Mdm::Service]
  belongs_to :service,
             class_name: 'Mdm::Service',
             inverse_of: :loots

  # @!attribute vuln_attempt
  #   Vuln attempt that gathered this loot.
  #
  #   @return [Mdm::VulnAttempt]
  has_one :vuln_attempt,
          class_name: 'Mdm::VulnAttempt',
          inverse_of: :loot

  # @!attribute [rw] workspace
  #   The workspace in which the loot is stored and the {#host} exists.
  #
  #   @return [Mdm::Workspace]
  belongs_to :workspace,
             class_name: 'Mdm::Workspace',
             inverse_of: :loots

  #
  # Attributes
  #

  # @!attribute [rw] content_type
  #   The mime/content type of the file at {#path}.  Used to server the file correctly so browsers understand whether
  #   to render or download the file.
  #
  #   @return [String]

  # @!attribute [rw] created_at
  #   When the loot was created.
  #
  #   @return [DateTime]

  # @!attribute [rw] data
  #   Loot data not stored in file at {#path}.
  #
  #   @return [String]

  # @!attribute [rw] ltype
  #   The type of loot
  #
  #   @return [String]

  # @!attribute [rw] info
  #   Information about the loot.
  #
  #   @return [String]

  # @!attribute [rw] name
  #   The name of the loot.
  #
  #   @return [String]

  # @!attribute [rw] path
  #   The on-disk path to the loot file.
  #
  #   @return [String]

  # @!attribute [rw] updated_at
  #   The last time the loot was updated.
  #
  #   @return [DateTime]

  #
  # Callbacks
  #

  before_destroy :delete_file

  #
  # Scopes
  #

  scope :search, lambda { |*args|
    joins(:host).
      where(
        'loots.ltype ILIKE ? ' +
          'OR loots.name ILIKE ? ' +
          'OR loots.info ILIKE ? ' +
          'OR loots.data ILIKE ? ' +
          'OR COALESCE(hosts.name, CAST(hosts.address AS TEXT)) ILIKE ?',
        "%#{args[0]}%", "%#{args[0]}%", "%#{args[0]}%", "%#{args[0]}%", "%#{args[0]}%"
      )
  }

  #
  # Serializations
  #

  serialize :data, MetasploitDataModels::Base64Serializer.new

  private

  # Deletes {#path} from disk.
  #
  # @todo https://www.pivotaltracker.com/story/show/49023795
  # @return [void]
  def delete_file
    c = Pro::Client.get rescue nil
    if c
      c.loot_delete_file(self[:id])
    else
      ::File.unlink(self.path) rescue nil
    end
  end

  public

  Metasploit::Concern.run(self)
end

