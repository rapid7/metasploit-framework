# The use of a {#core core credential} against a {#service service}.
class Metasploit::Credential::Login < ActiveRecord::Base
  extend ActiveSupport::Autoload

  include Metasploit::Model::Search

  #
  # Associations
  #
  
  # @!attribute tasks
  #   The `Mdm::Task`s using this to track what tasks interacted with a given core.
  #
  #   @return [ActiveRecord::Relation<Mdm::Task>]
  has_and_belongs_to_many :tasks,
                          -> { uniq },
                          class_name: "Mdm::Task", 
                          join_table: "credential_logins_tasks"

  # @!attribute core
  #   The {Metasploit::Credential::Core core credential} used to authenticate to {#service}.
  #
  #   @return [Metasploit::Credential::Core]
  belongs_to :core,
             class_name: 'Metasploit::Credential::Core',
             inverse_of: :logins,
             counter_cache: true

  # @!attribute service
  #   The service that either accepted the {#core core credential} as valid, invalid, or on which the
  #   {#core core credential} should be tested to see if it is valid.
  #
  #   @return [Mdm::Service]
  belongs_to :service,
             class_name: 'Mdm::Service',
             inverse_of: :logins

  #
  # through: :service
  #

  # @!attribute host
  #   The host on which {#service} runs.
  #
  #   @return [Mdm::Host]
  has_one :host,
          class_name: 'Mdm::Host',
          through: :service

  #
  # Attributes
  #

  # @!attribute access_level
  #   @note An empty string is converted to `nil` before saving.
  #
  #   A free-form text field that the user can use annotate the access level of this login, such as `'admin'`.
  #
  #   @return [String] The value entered by the user.
  #   @return [nil] When the user has not entered a value.

  # @!attribute created_at
  #   When this login was created.
  #
  #   @return [DateTime]

  # @!attribute last_attempted_at
  #   @note This is the last time this login was attempted and should be updated even if {#status} does not change.  If
  #   {#status} does not change, then normally {#updated_at} would be updated as the record would not save.
  #
  #   The last time a login was attempted.
  #
  #   @return [DateTime]

  # @!attribute status
  #   The status of this login, such as whether it is
  #   `Metasploit::Model::Login::Status::DENIED_ACCESS`,
  #   `Metasploit::Model::Login::Status::DISABLED`,
  #   `Metasploit::Model::Login::Status::LOCKED_OUT`,
  #   `Metasploit::Model::Login::Status::SUCCESSFUL`,
  #   `Metasploit::Model::Login::Status::UNABLE_TO_CONNECT`,
  #   `Metasploit::Model::Login::Status::UNTRIED`
  #
  #   @return [String] An element of `Metasploit::Model::Login::Status::ALL`

  # @!attribute updated_at
  #   The last time this login was updated.
  #
  #   @return [DateTime]

  #
  # Callbacks
  #

  before_validation :blank_to_nil

  #
  #
  # Search
  #
  #

  #
  # Search Associations
  #

  search_association :host
  search_association :service

  #
  # Search Attributes
  #

  search_attribute :access_level,
                   type: :string
  search_attribute :status,
                   type: {
                       set: :string
                   }

  #
  #
  # Validations
  #
  #

  #
  # Method Validations
  #

  validate :consistent_last_attempted_at
  validate :consistent_workspaces

  #
  # Attribute Validations
  #

  validates :core,
            presence: true
  validates :core_id,
            uniqueness: {
                scope: :service_id
            }
  validates :service,
            presence: true
  validates :status,
            inclusion: {
                in: Metasploit::Model::Login::Status::ALL
            }


  #
  # Scopes
  #

  # Finds all {Metasploit::Credential::Login} objects that are associated with a given `Mdm::Workspace`
  # @method in_workspace_including_hosts_and_services
  # @scope Metasploit::Credential::Login
  # @param workspace [Mdm::Workspace] the workspace to filter by
  # @return [ActiveRecord::Relation] containing the logins
  scope :in_workspace_including_hosts_and_services, ->(workspace) {
    host_workspace_column = Mdm::Host.arel_table[:workspace_id]
    joins(service: :host).includes(core: [:public, :private], service: :host).where(host_workspace_column.eq(workspace.id))
  }


  scope :by_host_id, ->(host_id) {
    host_id_column = Mdm::Host.arel_table[:id]
    joins(service: :host).includes(core: [:public,:private], service: :host).where(host_id_column.eq(host_id))
  }

  #
  # Class Methods
  #

  # Each username that is related to a login on the passed host and
  # the logins of particular statuses that are related
  # to that public, ordered by the login last attempt date.
  # @param host_id [Integer] the host to filter cores by
  # @return [Hash{String => Array}]
  def self.failed_logins_by_public(host_id)
    select(
      [
        Metasploit::Credential::Login[Arel.star],
        Metasploit::Credential::Public[:username]
      ]
    ).order(:last_attempted_at).
      joins(
      Metasploit::Credential::Login.join_association(:core),
      Metasploit::Credential::Core.join_association(:public, Arel::Nodes::OuterJoin)
    ).where(
      Metasploit::Credential::Core[:id].in(
        # We are concerned with per-username access attempts. This
        # can be across any of the cores on a host:
        Metasploit::Credential::Core.cores_from_host(host_id)
      ).and(
        Metasploit::Credential::Login[:status].in(
          [
            Metasploit::Model::Login::Status::DENIED_ACCESS,
            Metasploit::Model::Login::Status::DISABLED,
            Metasploit::Model::Login::Status::INCORRECT,
          ]
        ))
    ).group_by(&:username)
  end


  # The valid values for search {#status}.
  #
  # @return [Set<String>] `Metasploit::Model::Login::Status::ALL` as a `Set`.
  # @see Metasploit::Model::Search::Operation::Set#membership
  # @see Metasploit::Model::Search::Operator::Attribute#attribute_set
  def self.status_set
    @status_set ||= Set.new(Metasploit::Model::Login::Status::ALL)
  end

  #
  # Instance Methods
  #

  private

  # Converts blank {#access_level} to `nil`.
  #
  # @return [void]
  def blank_to_nil
    if access_level.blank?
      self.access_level = nil
    end
  end

  # Validates that {#last_attempted_at} is `nil` when {#status} is {Metasploit:Credential::Login::Status::UNTRIED} and
  # that {#last_attempted_at} is not `nil` when {#status} is not {Metasploit:Credential::Login::Status::UNTRIED}.
  #
  # @return [void]
  def consistent_last_attempted_at
    if status == Metasploit::Model::Login::Status::UNTRIED
      unless last_attempted_at.nil?
        errors.add(:last_attempted_at, :untried)
      end
    else
      if last_attempted_at.nil?
        errors.add(:last_attempted_at, :tried)
      end
    end
  end

  # Validates the {#service service's} `Mdm::Service#host`'s `Mdm::Host#workspace` matches {#core core's}
  # {Metasploit::Credential::Core#workspace}.
  def consistent_workspaces
    unless core.try(:workspace) == service.try(:host).try(:workspace)
      errors.add(:base, :inconsistent_workspaces)
    end
  end

  public

  Metasploit::Concern.run(self)
end
