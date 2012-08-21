module MetasploitDataModels::ActiveRecordModels::ModuleArch
  def self.included(base)
    base.class_eval{
      base.table_name = "module_archs"
      belongs_to :module_detail
      validate :name, :presence => true
    }
  end
end
