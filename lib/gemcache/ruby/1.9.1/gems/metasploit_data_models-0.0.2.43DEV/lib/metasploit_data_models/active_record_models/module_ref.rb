module MetasploitDataModels::ActiveRecordModels::ModuleRef
  def self.included(base)
    base.class_eval{
      base.table_name = "module_refs"
      belongs_to :module_detail
      validate :name, :presence => true
    }
  end
end
