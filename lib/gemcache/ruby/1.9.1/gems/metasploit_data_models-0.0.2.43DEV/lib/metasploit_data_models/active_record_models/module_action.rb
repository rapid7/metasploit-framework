module MetasploitDataModels::ActiveRecordModels::ModuleAction
  def self.included(base)
    base.class_eval{
      has_many :module_details_actions, :class_name => "Mdm::ModuleDetailAction"
      has_many :module_details, :through => :module_details_actions, :class_name => "Mdm::ModuleAction"
    }
  end
end
