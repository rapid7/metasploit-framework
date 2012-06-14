module MetasploitDataModels::ActiveRecordModels::ModuleDetailTarget
  def self.included(base)
    base.class_eval {
      base.table_name = "modules_details_targets"
      belongs_to :module_detail, :class_name => "Mdm::ModuleDetail"
      belongs_to :module_target, :class_name => "Mdm::ModuleTarget"
      validate :module_detail, :presence => true
      validate :module_target, :presence => true
    }
  end
end

