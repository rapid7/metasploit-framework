module MetasploitDataModels::ActiveRecordModels::ModuleDetailRef
  def self.included(base)
    base.class_eval {
      base.table_name = "modules_details_refs"
      belongs_to :module_detail, :class_name => "Mdm::ModuleDetail"
      belongs_to :module_ref, :class_name => "Mdm::ModuleRef"
    }
  end
end

