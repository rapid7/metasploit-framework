module MetasploitDataModels::ActiveRecordModels::ModuleAction
  def self.included(base)
    base.class_eval{
      base.table_name = "modules_actions"
      has_many :modules_details_actions, :class_name => "Mdm::ModuleDetailAction"
      has_many :modules_details, :through => :modules_details_actions, :class_name => "Mdm::ModuleAction", :source => :module_detail
    }
  end
end
