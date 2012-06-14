module MetasploitDataModels::ActiveRecordModels::VulnRef
  def self.included(base)
    base.class_eval {
      base.table_name = "vulns_refs"
      belongs_to :vuln, :class_name => "Mdm::Vuln"
      belongs_to :ref, :class_name => "Mdm::Ref"
    }
  end
end

