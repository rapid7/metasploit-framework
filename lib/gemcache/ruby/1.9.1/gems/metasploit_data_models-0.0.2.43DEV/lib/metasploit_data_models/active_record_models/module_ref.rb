module MetasploitDataModels::ActiveRecordModels::ModuleRef
  def self.included(base)
    base.class_eval{
      has_many :module_details_refs, :class_name => "Mdm::ModuleDetailRef"
      has_many :module_details, :through => :module_details_refs, :class_name => "Mdm::ModuleDetail"
    }
  end
end
