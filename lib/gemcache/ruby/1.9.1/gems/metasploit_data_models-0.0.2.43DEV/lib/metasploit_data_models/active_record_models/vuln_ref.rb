module MetasploitDataModels::ActiveRecordModels::VulnRef
  def self.included(base)
    base.class_eval {
      base.table_name = "vulns_refs"
    }
  end
end

