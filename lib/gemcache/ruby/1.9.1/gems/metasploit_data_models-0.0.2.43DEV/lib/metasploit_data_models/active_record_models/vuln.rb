module MetasploitDataModels::ActiveRecordModels::Vuln
  def self.included(base)
    base.class_eval {
      belongs_to :host, :class_name => "Mdm::Host", :counter_cache => :vuln_count
      belongs_to :service, :class_name => "Mdm::Service", :foreign_key => :service_id
      has_and_belongs_to_many :refs, :join_table => :vulns_refs, :class_name => "Mdm::Ref"
      has_many :vuln_details, :class_name => "Mdm::VulnDetail"
      has_many :vuln_attempts, :class_name => "Mdm::VulnAttempt"

      validates :name, :presence => true
      validates_associated :refs

      after_update :save_refs

      scope :search, lambda { |*args|
        where(["(vulns.name ILIKE ? or vulns.info ILIKE ? or refs.name ILIKE ?)",
          "%#{args[0]}%", "%#{args[0]}%", "%#{args[0]}%"
        ]).
        joins("LEFT OUTER JOIN vulns_refs ON vulns_refs.vuln_id=vulns.id LEFT OUTER JOIN refs ON refs.id=vulns_refs.ref_id")
      }

      private

      def save_refs
        refs.each { |ref| ref.save(:validate => false) }
      end
    }
  end
end
