module MetasploitDataModels::ActiveRecordModels::ModuleTarget
  def self.included(base)
    base.class_eval{
      has_many :module_details_targets, :class_name => "Mdm::ModuleDetailTarget"
      has_many :module_details, :through => :module_details_targets, :class_name => "Mdm::ModuleTarget"
    }
  end
end
