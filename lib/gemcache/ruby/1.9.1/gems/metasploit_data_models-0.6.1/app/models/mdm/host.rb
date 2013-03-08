
class Mdm::Host < ActiveRecord::Base
  include Mdm::Host::OperatingSystemNormalization

  #
  # Callbacks
  #

  before_destroy :cleanup_tags

  #
  # CONSTANTS
  #

  # Fields searched for the search scope
  SEARCH_FIELDS = [
      'address::text',
      'hosts.name',
      'os_name',
      'os_flavor',
      'os_sp',
      'mac',
      'purpose',
      'comments'
  ]

  #
  # Relations
  #

  has_many :exploit_attempts, :dependent => :destroy, :class_name => 'Mdm::ExploitAttempt'
  has_many :exploited_hosts, :dependent => :destroy, :class_name => 'Mdm::ExploitedHost'
  has_many :clients, :dependent => :delete_all, :class_name => 'Mdm::Client'
  has_many :host_details, :dependent => :destroy, :class_name => 'Mdm::HostDetail'
  # hosts_tags are cleaned up in before_destroy:
  has_many :hosts_tags, :class_name => 'Mdm::HostTag'
  has_many :loots, :dependent => :destroy, :class_name => 'Mdm::Loot', :order => 'loots.created_at desc'
  has_many :notes, :dependent => :delete_all, :class_name => 'Mdm::Note', :order => 'notes.created_at'
  has_many :services, :dependent => :destroy, :class_name => 'Mdm::Service', :order => 'services.port, services.proto'
  has_many :sessions, :dependent => :destroy, :class_name => 'Mdm::Session', :order => 'sessions.opened_at'
  has_many :vulns, :dependent => :delete_all, :class_name => 'Mdm::Vuln'
  belongs_to :workspace, :class_name => 'Mdm::Workspace'

  #
  # Through host_tags
  #
  has_many :tags, :through => :hosts_tags, :class_name => 'Mdm::Tag'

  #
  # Through services
  #
  has_many :creds, :through => :services, :class_name => 'Mdm::Cred'
  has_many :service_notes, :through => :services
  has_many :web_sites, :through => :services, :class_name => 'Mdm::WebSite'

  #
  # Nested Attributes
  # @note Must be declared after relations being referenced.
  #

  accepts_nested_attributes_for :services, :reject_if => lambda { |s| s[:port].blank? }, :allow_destroy => true

  #
  # Validations
  #

  validates :address,
            :exclusion => {
                :in => ['127.0.0.1']
            },
            :ip_format => true,
            :presence => true,
            :uniqueness => {
                :scope => :workspace_id,
                :unless => :ip_address_invalid?
            }
  validates :workspace, :presence => true

  #
  # Scopes
  #

  scope :alive, where({'hosts.state' => 'alive'})
  scope :flagged, where('notes.critical = true AND notes.seen = false').includes(:notes)
  scope :search,
        lambda { |*args|
          # @todo replace with AREL
          terms = SEARCH_FIELDS.collect { |field|
            "#{field} ILIKE ?"
          }
          disjunction = terms.join(' OR ')
          formatted_parameter = "%#{args[0]}%"
          parameters = [formatted_parameter] * SEARCH_FIELDS.length
          conditions = [disjunction] + parameters

          {
              :conditions => conditions
          }
        }
  scope :tag_search,
        lambda { |*args| where("tags.name" => args[0]).includes(:tags) }

  def attribute_locked?(attr)
    n = notes.find_by_ntype("host.updated.#{attr}")
    n && n.data[:locked]
  end

  def cleanup_tags
    # No need to keep tags with no hosts
    tags.each do |tag|
      tag.destroy if tag.hosts == [self]
    end
    # Clean up association table records
    Mdm::HostTag.delete_all("host_id = #{self.id}")
  end

  # This is replicated by the IpAddressValidator class. Had to put it here as well to avoid
  # SQL errors when checking address uniqueness.
  def ip_address_invalid?
    begin
      potential_ip = IPAddr.new(address)
      return true unless potential_ip.ipv4? || potential_ip.ipv6?
    rescue ArgumentError
      return true
    end
  end

  def is_vm?
    !!self.virtual_host
  end

  ActiveSupport.run_load_hooks(:mdm_host, self)
end

