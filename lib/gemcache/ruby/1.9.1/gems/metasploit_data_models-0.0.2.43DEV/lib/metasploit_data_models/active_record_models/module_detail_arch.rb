module MetasploitDataModels::ActiveRecordModels::ModuleDetailArch
  def self.included(base)
    base.class_eval {
      base.table_name = "modules_details_archs"
      belongs_to :module_detail, :class_name => "Mdm::ModuleDetail"
      belongs_to :module_arch, :class_name => "Mdm::ModuleArch"
    }
  end
end

