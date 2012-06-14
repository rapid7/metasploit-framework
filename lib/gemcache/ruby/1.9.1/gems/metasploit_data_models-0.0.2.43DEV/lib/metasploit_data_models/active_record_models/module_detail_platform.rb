module MetasploitDataModels::ActiveRecordModels::ModuleDetailPlatform
  def self.included(base)
    base.class_eval {
      base.table_name = "modules_details_platforms"
      belongs_to :module_detail, :class_name => "Mdm::ModuleDetail"
      belongs_to :module_platform, :class_name => "Mdm::ModulePlatform"
    }
  end
end

