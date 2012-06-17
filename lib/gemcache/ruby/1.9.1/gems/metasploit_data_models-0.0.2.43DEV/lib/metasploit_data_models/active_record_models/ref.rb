module MetasploitDataModels::ActiveRecordModels::Ref
  def self.included(base)
    base.class_eval{
      has_many :vulns, :through => :vulns_refs, :class_name => "Mdm::Vuln"
    }
  end
end
