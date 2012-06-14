module MetasploitDataModels::ActiveRecordModels::ModuleTarget
  def self.included(base)
    base.class_eval{
      base.table_name = "modules_targets"
      has_many :modules_details_targets, :class_name => "Mdm::ModuleDetailTarget"
      has_many :modules_details, :through => :modules_details_targets, :class_name => "Mdm::ModuleTarget", :source => :module_detail
    }
  end
end
