module MetasploitDataModels::ActiveRecordModels::VulnDetail
  def self.included(base)
    base.class_eval {
      belongs_to :vuln, :class_name => "Mdm::Vuln"
      validates :vuln_id, :presence => true
    }
  end
end
