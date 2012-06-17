module MetasploitDataModels::ActiveRecordModels::ModuleAction
  def self.included(base)
    base.class_eval{
      base.table_name = "module_actions"
      belongs_to :module_detail
      validate :name, :presence => true
    }
  end
end
