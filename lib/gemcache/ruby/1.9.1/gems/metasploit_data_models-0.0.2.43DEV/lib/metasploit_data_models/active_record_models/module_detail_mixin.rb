module MetasploitDataModels::ActiveRecordModels::ModuleDetailMixin
  def self.included(base)
    base.class_eval {
      base.table_name = "modules_details_mixins"
      belongs_to :module_detail, :class_name => "Mdm::ModuleDetail"
      belongs_to :module_mixin, :class_name => "Mdm::ModuleMixin"
      validate :module_detail, :presence => true
      validate :module_mixin, :presence => true
    }
  end
end

