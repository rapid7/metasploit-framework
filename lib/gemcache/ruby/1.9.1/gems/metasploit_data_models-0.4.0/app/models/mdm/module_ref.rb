class Mdm::ModuleRef < ActiveRecord::Base
  self.table_name = 'module_refs'

  #
  # Relations
  #

  belongs_to :module_detail, :class_name => 'Mdm::ModuleDetail'

  #
  # Validations
  #

  validate :name, :presence => true

  ActiveSupport.run_load_hooks(:mdm_module_ref, self)
end
