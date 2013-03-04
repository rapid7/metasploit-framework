class Mdm::Workspace < ActiveRecord::Base
  #
  # Callbacks
  #

  before_save :normalize

  #
  # CONSTANTS
  #

  DEFAULT = 'default'

  #
  # Relations
  #

  has_many :creds, :through => :services, :class_name => 'Mdm::Cred'
  has_many :events, :class_name => 'Mdm::Event'
  has_many :hosts, :dependent => :destroy, :class_name => 'Mdm::Host'
  has_many :imported_creds, :dependent => :destroy, :class_name => 'Mdm::ImportedCred'
  has_many :listeners, :dependent => :destroy, :class_name => 'Mdm::Listener'
  has_many :notes, :class_name => 'Mdm::Note'
  belongs_to :owner, :class_name => 'Mdm::User', :foreign_key => 'owner_id'
  has_many :report_templates, :dependent => :destroy, :class_name => 'Mdm::ReportTemplate'
  has_many :reports, :dependent => :destroy, :class_name => 'Mdm::Report'
  has_many :tasks, :dependent => :destroy, :class_name => 'Mdm::Task', :order => 'created_at DESC'
  has_and_belongs_to_many :users, :join_table => 'workspace_members', :uniq => true, :class_name => 'Mdm::User'

  #
  # Through :hosts
  #
  has_many :clients, :through => :hosts, :class_name => 'Mdm::Client'
  has_many :exploited_hosts, :through => :hosts, :class_name => 'Mdm::ExploitedHost'
  has_many :loots, :through => :hosts, :class_name => 'Mdm::Loot'
  has_many :vulns, :through => :hosts, :class_name => 'Mdm::Vuln'
  has_many :services, :through => :hosts, :class_name => 'Mdm::Service', :foreign_key => 'service_id'
  has_many :sessions, :through => :hosts, :class_name => 'Mdm::Session'

  #
  # Validations
  #

  validates :name, :presence => true, :uniqueness => true, :length => {:maximum => 255}
  validates :description, :length => {:maximum => 4096}
  validate :boundary_must_be_ip_range

  #
  # If limit_to_network is disabled, this will always return true.
  # Otherwise, return true only if all of the given IPs are within the project
  # boundaries.
  #
  def allow_actions_on?(ips)
    return true unless limit_to_network
    return true unless boundary
    return true if boundary.empty?
    boundaries = Shellwords.split(boundary)
    return true if boundaries.empty? # It's okay if there is no boundary range after all
    given_range = Rex::Socket::RangeWalker.new(ips)
    return false unless given_range # Can't do things to nonexistant IPs
    allowed = false
    boundaries.each do |boundary_range|
      ok_range = Rex::Socket::RangeWalker.new(boundary)
      allowed = true if ok_range.include_range? given_range
    end
    return allowed
  end

  def boundary_must_be_ip_range
    errors.add(:boundary, "must be a valid IP range") unless valid_ip_or_range?(boundary)
  end

  def creds
    Mdm::Cred.find(
        :all,
        :include => {:service => :host},
        :conditions => ["hosts.workspace_id = ?", self.id]
    )
  end

  def self.default
    find_or_create_by_name(DEFAULT)
  end

  def default?
    name == DEFAULT
  end

  #
  # This method iterates the creds table calling the supplied block with the
  # cred instance of each entry.
  #
  def each_cred(&block)
    creds.each do |cred|
      block.call(cred)
    end
  end

  def each_host_tag(&block)
    host_tags.each do |host_tag|
      block.call(host_tag)
    end
  end

  def host_tags
    Mdm::Tag.find(
        :all,
        :include => :hosts,
        :conditions => ["hosts.workspace_id = ?", self.id]
    )
  end

  def web_forms
    query = <<-EOQ
          SELECT DISTINCT web_forms.*
          FROM hosts, services, web_sites, web_forms
          WHERE hosts.workspace_id = #{id} AND
            services.host_id = hosts.id AND
            web_sites.service_id = services.id AND
            web_forms.web_site_id = web_sites.id
    EOQ
    Mdm::WebForm.find_by_sql(query)
  end

  def web_pages
    query = <<-EOQ
          SELECT DISTINCT web_pages.*
            FROM hosts, services, web_sites, web_pages
            WHERE hosts.workspace_id = #{id} AND
            services.host_id = hosts.id AND
            web_sites.service_id = services.id AND
            web_pages.web_site_id = web_sites.id
    EOQ
    Mdm::WebPage.find_by_sql(query)
  end

  def web_sites
    query = <<-EOQ
          SELECT DISTINCT web_sites.*
            FROM hosts, services, web_sites
            WHERE hosts.workspace_id = #{id} AND
            services.host_id = hosts.id AND
            web_sites.service_id = services.id
    EOQ
    Mdm::WebSite.find_by_sql(query)
  end

  def web_vulns
    query = <<-EOQ
          SELECT DISTINCT web_vulns.*
          FROM hosts, services, web_sites, web_vulns
            WHERE hosts.workspace_id = #{id} AND
            services.host_id = hosts.id AND
            web_sites.service_id = services.id AND
            web_vulns.web_site_id = web_sites.id
    EOQ
    Mdm::WebVuln.find_by_sql(query)
  end

  def unique_web_forms
    query = <<-EOQ
          SELECT DISTINCT web_forms.web_site_id, web_forms.path, web_forms.method, web_forms.query  
            FROM hosts, services, web_sites, web_forms  
            WHERE hosts.workspace_id = #{id} AND        
            services.host_id = hosts.id AND         
            web_sites.service_id = services.id AND  
            web_forms.web_site_id = web_sites.id
    EOQ
    Mdm::WebForm.find_by_sql(query)
  end

  def web_unique_forms(addrs=nil)
    forms = unique_web_forms
    if addrs
      forms.reject!{|f| not addrs.include?( f.web_site.service.host.address ) }
    end
    forms
  end

  private

  def normalize
    boundary.strip! if boundary
  end

  def valid_ip_or_range?(string)
    begin
      Rex::Socket::RangeWalker.new(string)
    rescue
      return false
    end
  end

  ActiveSupport.run_load_hooks(:mdm_workspace, self)
end

