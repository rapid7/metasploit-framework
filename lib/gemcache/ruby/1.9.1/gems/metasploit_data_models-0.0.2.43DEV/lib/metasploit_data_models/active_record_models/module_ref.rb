module MetasploitDataModels::ActiveRecordModels::ModuleRef
  def self.included(base)
    base.class_eval{
      base.table_name = "modules_refs"
      has_many :modules_details_refs, :class_name => "Mdm::ModuleDetailRef"
      has_many :modules_details, :through => :modules_details_refs, :class_name => "Mdm::ModuleDetail", :source => :module_detail
    }
  end
end
