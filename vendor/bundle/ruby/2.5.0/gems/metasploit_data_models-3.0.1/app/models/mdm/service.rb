# A service, such as an ssh server or web server, running on a {#host}.
class Mdm::Service < ActiveRecord::Base
  include Metasploit::Model::Search

  #
  # CONSTANTS
  #

  # Valid values for {#proto}.
  PROTOS = %w{tcp udp}

  # Valid values for {#state}.
  STATES = ['open', 'closed', 'filtered', 'unknown']

  #
  # Associations
  #

  # @!attribute creds
  #   Credentials gathered from this service.
  #
  #   @return [ActiveRecord::Relation<Mdm::Cred>]
  has_many :creds,
           class_name: 'Mdm::Cred',
           dependent: :destroy,
           inverse_of: :service

  # @!attribute exploit_attempts
  #   Exploit attempts against this service.
  #
  #   @return [ActiveRecord::Relation<Mdm::ExploitAttempt>]
  has_many :exploit_attempts,
           class_name: 'Mdm::ExploitAttempt',
           dependent: :destroy,
           inverse_of: :service

  # @!attribute exploited_hosts
  #   @todo MSP-2732
  #   @return [Array<Mdm::ExploitHost>]
  has_many :exploited_hosts,
           class_name: 'Mdm::ExploitedHost',
           dependent: :destroy,
           inverse_of: :service

  # @!attribute host
  #   The host on which this service runs.
  #
  #   @return [Mdm::Host]
  belongs_to :host,
             class_name: 'Mdm::Host',
             counter_cache: :service_count,
             inverse_of: :services

  # @!attribute loots
  #   Loot gathers from this service.
  #
  #   @return [ActiveRecord::Relation<Mdm::Loot>]
  has_many :loots,
           class_name: 'Mdm::Loot',
           dependent: :destroy,
           inverse_of: :service

  # @!attribute notes
  #   Notes about this service.
  #
  #   @return [ActiveRecord::Relation<Mdm::Note>]
  has_many :notes,
           class_name: 'Mdm::Note',
           dependent: :destroy,
           inverse_of: :service

  # @!attribute [rw] task_services
  #   Details about what Tasks touched this service
  #
  #   @return [Array<Mdm::TaskService>]
  has_many :task_services,
           class_name: 'Mdm::TaskService',
           dependent: :destroy,
           inverse_of: :service

  # @!attribute vulns
  #   Vulnerabilities found in this service.
  #
  #   @return [ActiveRecord::Relation<Mdm::Vuln>]
  has_many :vulns,
           class_name: 'Mdm::Vuln',
           dependent: :destroy,
           inverse_of: :service

  # @!attribute web_sites
  #   Web sites running on top of this service.
  #
  #   @return [ActiveRecord::Relation<Mdm::WebSite>]
  has_many :web_sites,
           class_name: 'Mdm::WebSite',
           dependent: :destroy,
           inverse_of: :service

  #
  # through: :task_services
  #

  # @!attribute [rw] tasks
  #   Tasks that touched this service
  #
  #   @return [Array<Mdm::Task>]
  has_many :tasks, :through => :task_services, :class_name => 'Mdm::Task'

  #
  # Through :web_sites
  #

  # @!attribute [r] web_pages
  #   Web pages in the {#web_sites} on top of this service.
  #
  #   @return [Array<Mdm::WebPages>]
  has_many :web_pages, :through => :web_sites, :class_name => 'Mdm::WebPage'

  # @!attribute [r] web_forms
  #   Form in the {#web_sites} on top of this service.
  #
  #   @return [Array<Mdm::WebForm>]
  has_many :web_forms, :through => :web_sites, :class_name => 'Mdm::WebForm'

  # @!attribute [r] web_vulns
  #   Vulnerabilities found in the {#web_sites} on top of this service.
  #
  #   @return [Array<Mdm::WebVuln>]
  has_many :web_vulns, :through => :web_sites, :class_name => 'Mdm::WebVuln'

  #
  # Attributes
  #

  # @!attribute [rw] info
  #   Additional information about the service that does not fit in the {#name} or {#proto}.
  #
  #   @return [String]

  # @!attribute [rw] port
  #   The port on which this service runs on the {#host}.
  #
  #   @return [Integer]

  # @!attribute [rw] name
  #    The name of the service.
  #
  #    @return [String]

  # @!attribute [rw] proto
  #   The protocol used by this service
  #
  #   @return [String]

  # @!attribute [rw] state
  #   Whether this service is opened, closed, filtered, or in an unknown state.
  #
  #   @return [String] element of {STATES}.

  #
  # Callbacks
  #

  after_save :normalize_host_os

  #
  # Scopes
  #

  scope :inactive, -> { where("services.state != 'open'") }
  scope :with_state, lambda { |a_state|  where("services.state = ?", a_state)}
  scope :search, lambda { |*args|
    joins(:host).
      where(
        'services.name ILIKE ? OR ' +
          'services.info ILIKE ? OR ' +
          'services.proto ILIKE ? OR ' +
          'services.port = ? OR ' +
          'COALESCE(hosts.name, CAST(hosts.address AS TEXT)) ILIKE ?',
         "%#{args[0]}%", "%#{args[0]}%", "%#{args[0]}%", (args[0].to_i > 0) ? args[0].to_i : 99999, "%#{args[0]}%"
      )
  }

  #
  #
  # Search
  #
  #

  #
  # Search Associations
  #

  search_associations host: :tags

  #
  # Search Attributes
  #

  search_attribute :info,
                   type: :string
  search_attribute :name,
                   type: :string
  search_attribute :proto,
                   type: {
                       set: :string
                   }

  #
  # Search Withs
  #

  search_with MetasploitDataModels::Search::Operator::Port::List

  #
  # Validations
  #
  validates :port,
            numericality: {
                only_integer: true
            },
            inclusion: {
                in: 1..65535
            }
  validates :port,
            uniqueness: {
              message: 'already exists on this host and protocol',
              scope: [
                :host_id,
                :proto
              ]
            }
  validates :proto,
            inclusion: {
                in: PROTOS
            }


  #
  # Class Methods
  #

  # Set of searchable values for {#proto}.
  #
  # @return [Set<String>] {PROTOS} as a `Set`.
  # @see Metasploit::Model::Search::Operation::Set#membership
  # @see Metasploit::Model::Search::Operator::Attribute#attribute_set
  def self.proto_set
    @proto_set ||= Set.new(PROTOS)
  end

  #
  # Instance Methods
  #

  # {Mdm::Host::OperatingSystemNormalization#normalize_os Normalizes the host operating system} whenever {#info} has
  # changed.
  #
  # @return [void]
  def normalize_host_os
    if info_changed? && host.workspace.present? && !host.workspace.import_fingerprint
      host.normalize_os
    end
  end

  Metasploit::Concern.run(self)
end
