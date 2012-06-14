module MetasploitDataModels::ActiveRecordModels::ModulePlatform
  def self.included(base)
    base.class_eval{
      has_many :module_details_platforms, :class_name => "Mdm::ModuleDetailPlatform"
      has_many :module_details, :through => :module_details_platforms, :class_name => "Mdm::ModulePlatform"
    }
  end
end
