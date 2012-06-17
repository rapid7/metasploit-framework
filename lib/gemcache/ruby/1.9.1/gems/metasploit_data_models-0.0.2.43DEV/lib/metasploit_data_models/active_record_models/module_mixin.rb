module MetasploitDataModels::ActiveRecordModels::ModuleMixin
  def self.included(base)
    base.class_eval{
      base.table_name = "modules_mixin"
      belongs_to :module_detail
      validate :name, :presence => true
    }
  end
end
