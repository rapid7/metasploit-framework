module MetasploitDataModels::ActiveRecordModels::ModuleTarget
  def self.included(base)
    base.class_eval{
      base.table_name = "module_targets"
      belongs_to :module_detail
      validate :name, :presence => true
    }
  end
end
