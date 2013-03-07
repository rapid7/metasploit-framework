class Mdm::Vuln < ActiveRecord::Base
  #
  # Callbacks
  #

  after_update :save_refs

  #
  # Relations
  #

  belongs_to :host, :class_name => 'Mdm::Host', :counter_cache => :vuln_count
  belongs_to :service, :class_name => 'Mdm::Service', :foreign_key => :service_id
  has_many :vuln_attempts,  :dependent => :destroy, :class_name => 'Mdm::VulnAttempt'
  has_many :vuln_details,  :dependent => :destroy, :class_name => 'Mdm::VulnDetail'
  has_many :vulns_refs, :class_name => 'Mdm::VulnRef'

  #
  # Through :vuln_refs
  #
  has_many :refs, :through => :vulns_refs, :class_name => 'Mdm::Ref'

  #
  # Scopes
  #

  scope :search, lambda { |*args|
    where(
        [
            '(vulns.name ILIKE ? or vulns.info ILIKE ? or refs.name ILIKE ?)',
            "%#{args[0]}%",
            "%#{args[0]}%",
            "%#{args[0]}%"
        ]
    ).joins(
        'LEFT OUTER JOIN vulns_refs ON vulns_refs.vuln_id=vulns.id LEFT OUTER JOIN refs ON refs.id=vulns_refs.ref_id'
    )
  }

  #
  # Validations
  #

  validates :name, :presence => true
  validates_associated :refs

  private

  def before_destroy
    Mdm::VulnRef.delete_all('vuln_id = ?', self.id)
    Mdm::VulnDetail.delete_all('vuln_id = ?', self.id)
    Mdm::VulnAttempt.delete_all('vuln_id = ?', self.id)
  end

  def save_refs
    refs.each { |ref| ref.save(:validate => false) }
  end

  ActiveSupport.run_load_hooks(:mdm_vuln, self)
end
