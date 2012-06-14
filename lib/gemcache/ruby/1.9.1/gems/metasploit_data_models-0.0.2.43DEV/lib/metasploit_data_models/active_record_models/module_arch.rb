module MetasploitDataModels::ActiveRecordModels::ModuleArch
  def self.included(base)
    base.class_eval{
      has_many :module_details_archs, :class_name => "Mdm::ModuleDetailArch"
      has_many :module_details, :through => :module_details_archs, :class_name => "Mdm::ModuleArch"
    }
  end
end
