class Mdm::Service < ActiveRecord::Base
  #
  # Callbacks
  #

  after_save :normalize_host_os

  #
  # CONSTANTS
  #

  STATES = ['open', 'closed', 'filtered', 'unknown']

  #
  # Relations
  #

  has_many :creds, :dependent => :destroy, :class_name => 'Mdm::Cred'
  has_many :exploited_hosts, :dependent => :destroy, :class_name => 'Mdm::ExploitedHost'
  belongs_to :host, :class_name => 'Mdm::Host', :counter_cache => :service_count
  has_many :notes, :dependent => :destroy, :class_name => 'Mdm::Note'
  has_many :vulns, :dependent => :destroy, :class_name => 'Mdm::Vuln'
  has_many :web_sites, :dependent => :destroy, :class_name => 'Mdm::WebSite'

  #
  # Through :web_sites
  #
  has_many :web_pages, :through => :web_sites, :class_name => 'Mdm::WebPage'
  has_many :web_forms, :through => :web_sites, :class_name => 'Mdm::WebForm'
  has_many :web_vulns, :through => :web_sites, :class_name => 'Mdm::WebVuln'

  #
  # Scopes
  #

  scope :inactive, where("services.state != 'open'")
  scope :with_state, lambda { |a_state|  where("services.state = ?", a_state)}
  scope :search, lambda { |*args|
    where([
              "services.name ILIKE ? OR " +
                  "services.info ILIKE ? OR " +
                  "services.proto ILIKE ? OR " +
                  "services.port = ? ",
              "%#{args[0]}%", "%#{args[0]}%", "%#{args[0]}%", (args[0].to_i > 0) ? args[0].to_i : 99999
          ])
  }

  def normalize_host_os
    if info_changed?
      host.normalize_os
    end
  end

  ActiveSupport.run_load_hooks(:mdm_service, self)
end

