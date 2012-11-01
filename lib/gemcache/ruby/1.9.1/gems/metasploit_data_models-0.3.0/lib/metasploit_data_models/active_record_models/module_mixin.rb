module MetasploitDataModels::ActiveRecordModels::ModuleMixin
  def self.included(base)
    base.class_eval{
      base.table_name = "module_mixins"
      belongs_to :module_detail
      validate :name, :presence => true
    }
  end
end
