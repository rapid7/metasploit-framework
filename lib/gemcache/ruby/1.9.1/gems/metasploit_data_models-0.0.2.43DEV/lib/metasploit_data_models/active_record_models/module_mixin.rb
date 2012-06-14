module MetasploitDataModels::ActiveRecordModels::ModuleMixin
  def self.included(base)
    base.class_eval{
      has_many :module_details_mixins, :class_name => "Mdm::ModuleDetailMixin"
      has_many :module_details, :through => :module_details_mixins, :class_name => "Mdm::ModuleDetail"
    }
  end
end
