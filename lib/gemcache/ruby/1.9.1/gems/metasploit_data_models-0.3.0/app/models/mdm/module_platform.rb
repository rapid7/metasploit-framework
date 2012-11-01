module MetasploitDataModels::ActiveRecordModels::ModulePlatform
  def self.included(base)
    base.class_eval{
      base.table_name = "module_platforms"
      belongs_to :module_detail
      validate :name, :presence => true
    }
  end
end
