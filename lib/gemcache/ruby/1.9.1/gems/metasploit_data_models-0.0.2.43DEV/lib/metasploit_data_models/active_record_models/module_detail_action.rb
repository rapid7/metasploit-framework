module MetasploitDataModels::ActiveRecordModels::ModuleDetailAction
  def self.included(base)
    base.class_eval {
      base.table_name = "module_details_actions"
      belongs_to :module_detail, :class_name => "Mdm::ModuleDetail"
      belongs_to :module_action, :class_name => "Mdm::ModuleAction"
    }
  end
end

