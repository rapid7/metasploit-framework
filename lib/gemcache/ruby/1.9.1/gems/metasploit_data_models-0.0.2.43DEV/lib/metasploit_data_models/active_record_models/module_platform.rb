module MetasploitDataModels::ActiveRecordModels::ModulePlatform
  def self.included(base)
    base.class_eval{
      base.table_name = "modules_platforms"
      has_many :modules_details_platforms, :class_name => "Mdm::ModuleDetailPlatform"
      has_many :modules_details, :through => :modules_details_platforms, :class_name => "Mdm::ModulePlatform", :source => :module_detail
    }
  end
end
