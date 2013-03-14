class Mdm::ModuleMixin < ActiveRecord::Base
  self.table_name = 'module_mixins'

  #
  # Relations
  #

  belongs_to :module_detail, :class_name => 'Mdm::ModuleDetail'

  #
  # Validation
  #

  validate :name, :presence => true

  ActiveSupport.run_load_hooks(:mdm_module_mixin, self)
end
