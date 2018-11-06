# Core credential that combines {#private}, {#public}, and/or {#realm} so that {Metasploit::Credential::Private} or
# {Metasploit::Credential::Public} that are gathered from a {Metasploit::Credential::Realm} are properly scoped when
# used.
#
# A core credential must always have an {#origin}, but only needs 1 of {#private}, {#public}, or {#realm} set.
class Metasploit::Credential::Core < ActiveRecord::Base
  include Metasploit::Model::Search
  include Metasploit::Credential::CoreValidations

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
                          join_table: "credential_cores_tasks"

  # @!attribute logins
  #   The {Metasploit::Credential::Login logins} using this core credential to log into a service.
  #
  #   @return [ActiveRecord::Relation<Metasploit::Credential::Login>]
  has_many :logins,
           class_name: 'Metasploit::Credential::Login',
           dependent: :destroy,
           inverse_of: :core

  # @!attribute origin
  #   The origin of this core credential.
  #
  #   @return [Metasploit::Credential::Origin::Import] if this core credential was bulk imported by a
  #     {Metasploit::Credential::Origin::Import#task task}.
  #   @return [Metasploit::Credential::Origin::Manual] if this core credential was manually entered by a
  #     {Metasploit::Credential::Origin::Manual#user user}.
  #   @return [Metasploit::Credential::Origin::Service] if this core credential was gathered from a
  #     {Metasploit::Credential::Origin::Service#service service} using an
  #     {Metasploit::Credential::Origin::Service#module_full_name auxiliary or exploit module}.
  #   @return [Metasploit::Credential::Origin::Session] if this core credential was gathered using a
  #     {Metasploit::Credential::Origin::Session#post_reference_name post module} attached to a
  #     {Metasploit::Credential::Origin::Session#session session}.
  belongs_to :origin,
             polymorphic: true

  # @!attribute private
  #   The {Metasploit::Credential::Private} either gathered from {#realm} or used to
  #   {Metasploit::Credential::ReplayableHash authenticate to the realm}.
  #
  #   @return [Metasploit::Credential::Private, nil]
  belongs_to :private,
             class_name: 'Metasploit::Credential::Private',
             inverse_of: :cores

  # @!attribute public
  #   The {Metasploit::Credential::Public} gathered from {#realm}.
  #
  #   @return [Metasploit::Credential::Public, nil]
  belongs_to :public,
             class_name: 'Metasploit::Credential::Public',
             inverse_of: :cores

  # @!attribute realm
  #   The {Metasploit::Credential::Realm} where {#private} and/or {#public} was gathered and/or the
  #   {Metasploit::Credential::Realm} to which {#private} and/or {#public} can be used to authenticate.
  #
  #   @return [Metasploit::Credential::Realm, nil]
  belongs_to :realm,
             class_name: 'Metasploit::Credential::Realm',
             inverse_of: :cores

  # @!attribute workspace
  #   The `Mdm::Workspace` to which this core credential is scoped.  Used to limit mixing of different networks
  #   credentials.
  #
  #   @return [Mdm::Workspace]
  belongs_to :workspace,
             class_name: 'Mdm::Workspace',
             inverse_of: :core_credentials

  #
  # Attributes
  #

  # @!attribute created_at
  #   When this core credential was created.
  #
  #   @return [DateTime]

  # @!attribute updated_at
  #   When this core credential was last updated.
  #
  #   @return [DateTime]

  #
  #
  # Validations
  #
  #

  #
  # Method Validations
  #

  validate :consistent_workspaces
  validates :origin,
            presence: true

  #
  # Scopes
  #


  # Finds Cores that have successfully logged into a given host
  #
  # @method login_host_id(host_id)
  # @scope Metasploit::Credential::Core
  # @param host_id [Integer] the host to look for
  # @return [ActiveRecord::Relation] scoped to that host
  scope :login_host_id, lambda { |host_id|
    joins(logins: { service: :host }).where(Mdm::Host.arel_table[:id].eq(host_id))
  }

  # JOINs in origins of a specific type
  #
  # @method origins(origin_class)
  # @scope Metasploit::Credential::Core
  # @param origin_class [ActiveRecord::Base] the Origin class to look up
  # @param table_alias [String] an alias for the JOINed table, defaults to the table name
  # @return [ActiveRecord::Relation] scoped to that origin
  scope :origins, lambda { |origin_class, table_alias=nil|
    core_table   = Metasploit::Credential::Core.arel_table
    origin_table = origin_class.arel_table.alias(table_alias || origin_class.table_name)
    origin_joins = core_table.join(origin_table).on(origin_table[:id].eq(core_table[:origin_id])
      .and(core_table[:origin_type].eq(origin_class.to_s)))
    joins(origin_joins.join_sources)
  }

  # Finds Cores that have an origin_type of Service and are attached to the given host
  #
  # @method origin_service_host_id(host_id)
  # @scope Metasploit::Credential::Core
  # @param host_id [Integer] the host to look up
  # @return [ActiveRecord::Relation] scoped to that host
  scope :origin_service_host_id, lambda { |host_id|
    core_table = Metasploit::Credential::Core.arel_table
    host_table = Mdm::Host.arel_table
    services_hosts.select(core_table[:id]).where(host_table[:id].eq(host_id))
  }

  # Finds Cores that have an origin_type of Session that were collected from the given host
  #
  # @method origin_session_host_id(host_id)
  # @scope Metasploit::Credential::Core
  # @param host_id [Integer] the host to look up
  # @return [ActiveRecord::Relation] scoped to that host
  scope :origin_session_host_id, lambda { |host_id|
    core_table = Metasploit::Credential::Core.arel_table
    host_table = Mdm::Host.arel_table
    sessions_hosts.select(core_table[:id]).where(host_table[:id].eq(host_id))
  }

  # Adds a JOIN for the Service and Host that a Core with an Origin type of Service would have
  #
  # @method services_hosts
  # @scope Metasploit::Credential::Core
  # @return [ActiveRecord::Relation] with a JOIN on origin: services: hosts
  scope :services_hosts, lambda {
    core_table    = Metasploit::Credential::Core.arel_table
    service_table = Mdm::Service.arel_table
    host_table    = Mdm::Host.arel_table
    origin_table  = Metasploit::Credential::Origin::Service.arel_table.alias('origins_for_service')

    origins(Metasploit::Credential::Origin::Service, 'origins_for_service').joins(
      core_table.join(service_table).on(service_table[:id].eq(origin_table[:service_id])).join_sources,
      core_table.join(host_table).on(host_table[:id].eq(service_table[:host_id])).join_sources
    )
  }

  # Adds a JOIN for the Session and Host that a Core with an Origin type of Session would have
  #
  # @method sessions_hosts
  # @scope Metasploit::Credential::Core
  # @return [ActiveRecord::Relation] with a JOIN on origin: sessions: hosts
  scope :sessions_hosts, lambda {
    core_table    = Metasploit::Credential::Core.arel_table
    session_table = Mdm::Session.arel_table
    host_table    = Mdm::Host.arel_table
    origin_table  = Metasploit::Credential::Origin::Session.arel_table.alias('origins_for_session')

    origins(Metasploit::Credential::Origin::Session, 'origins_for_session').joins(
      core_table.join(session_table).on(session_table[:id].eq(origin_table[:session_id])).join_sources,
      core_table.join(host_table).on(host_table[:id].eq(session_table[:host_id])).join_sources
    )
  }

  # Finds all Cores that have been collected in some way from a Host
  #
  # @method originating_host_id
  # @scope Metasploit::Credential::Core
  # @param host_id [Integer] the host to look up
  # @return [ActiveRecord::Relation] that contains related Cores
  scope :originating_host_id, ->(host_id) {
    where(
      Metasploit::Credential::Core[:id].in(
        Metasploit::Credential::Core.cores_from_host(host_id)
      )
    )
  }

  # Finds Cores that are attached to a given workspace
  #
  # @method workspace_id(id)
  # @scope Metasploit::Credential::Core
  # @param id [Integer] the workspace to look in
  # @return [ActiveRecord::Relation] scoped to the workspace
  scope :workspace_id, ->(id) {
    where(workspace_id: id)
  }

  # Eager loads {Metasploit::Credential::Login} objects associated to Cores
  #
  # @method with_logins
  # @return [ActiveRecord::Relation]
  scope :with_logins, ->() {
    includes(:logins)
  }

  # Eager loads {Metasploit::Credential::Public} objects associated to Cores
  #
  # @method with_public
  # @return [ActiveRecord::Relation]
  scope :with_public, ->() {
    includes(:public)
  }

  # Eager loads {Metasploit::Credential::Private} objects associated to Cores
  #
  # @method with_private
  # @return [ActiveRecord::Relation]
  scope :with_private, ->() {
    includes(:private)
  }

  # Eager loads {Metasploit::Credential::Realm} objects associated to Cores
  #
  # @method with_realm
  # @return [ActiveRecord::Relation]
  scope :with_realm, ->() {
    includes(:realm)
  }

  #
  #
  # Search
  #
  #

  #
  # Search Associations
  #

  search_association :logins
  search_association :private
  search_association :public
  search_association :realm

  #
  # Class Methods
  #

  # Provides UNIONing cores from a host via
  # service origins or via session origins.
  # @param host_id [Integer]
  # @return [String]
  def self.cores_from_host(host_id)
    left = origin_service_host_id(host_id).ast
    right = origin_session_host_id(host_id).ast

    Arel::Nodes::UnionAll.new(
      left,
      right
    )
  end

  #
  # Instance Methods
  #

  private

  # Validates that the direct {#workspace} is consistent with the `Mdm::Workspace` accessible through the {#origin}.
  #
  # @return [void]
  def consistent_workspaces
    case origin
      when Metasploit::Credential::Origin::Manual
        user = origin.user

        # admins can access any workspace so there's no inconsistent workspace
        unless user &&
               (
                user.admin ||
                # use database query when possible
                (
                 user.persisted? &&
                 user.workspaces.exists?(self.workspace.id)
                ) ||
                # otherwise fall back to in-memory query
                user.workspaces.include?(self.workspace)
               )
          errors.add(:workspace, :origin_user_workspaces)
        end
      when Metasploit::Credential::Origin::Service
        unless self.workspace == origin.service.try(:host).try(:workspace)
          errors.add(:workspace, :origin_service_host_workspace)
        end
      when Metasploit::Credential::Origin::Session
        unless self.workspace == origin.session.try(:host).try(:workspace)
          errors.add(:workspace, :origin_session_host_workspace)
        end
    end
  end

  public

  Metasploit::Concern.run(self)
end
