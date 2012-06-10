module MetasploitDataModels::ActiveRecordModels::VulnAttempt
  def self.included(base)
    base.class_eval {
      belongs_to :vuln, :class_name => "Mdm::VulnAttempt"
      validates :vuln_id, :presence => true
    }
  end
end
