module MetasploitDataModels::ActiveRecordModels::ModuleMixin
  def self.included(base)
    base.class_eval{
      base.table_name = "modules_mixins"
      has_many :modules_details_mixins, :class_name => "Mdm::ModuleDetailMixin"
      has_many :modules_details, :through => :modules_details_mixins, :class_name => "Mdm::ModuleDetail", :source => :module_detail
      validate :name, :presence => true, :uniqueness => true
    }
  end
end
