module MetasploitDataModels::ActiveRecordModels::ModuleDetailTarget
  def self.included(base)
    base.class_eval {
      base.table_name = "module_details_targets"
      belongs_to :module_detail, :class_name => "Mdm::ModuleDetail"
      belongs_to :module_target, :class_name => "Mdm::ModuleTarget"
    }
  end
end

