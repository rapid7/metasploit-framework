module MetasploitDataModels::ActiveRecordModels::ModuleDetailAction
  def self.included(base)
    base.class_eval {
      base.table_name = "modules_details_actions"
      belongs_to :module_detail, :class_name => "Mdm::ModuleDetail"
      belongs_to :module_action, :class_name => "Mdm::ModuleAction"
      validate :module_detail, :presence => true
      validate :module_action, :presence => true
    }
  end
end


