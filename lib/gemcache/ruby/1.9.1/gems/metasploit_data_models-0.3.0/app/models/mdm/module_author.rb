module MetasploitDataModels::ActiveRecordModels::ModuleAuthor
  def self.included(base)
    base.class_eval{
      base.table_name = "module_authors"
      belongs_to :module_detail
      validate :name, :presence => true
    }
  end
end
