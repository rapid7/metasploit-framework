module MetasploitDataModels::ActiveRecordModels::VulnRef
  def self.included(base)
    base.class_eval {
      base.table_name = "vulns_refs"
      belongs_to :ref
      belongs_to :vuln
    }
  end
end

