module MetasploitDataModels::ActiveRecordModels::ModuleDetailMixin
  def self.included(base)
    base.class_eval {
      base.table_name = "module_details_mixins"
      belongs_to :module_detail, :class_name => "Mdm::ModuleDetail"
      belongs_to :module_mixin, :class_name => "Mdm::ModuleMixin"
    }
  end
end

