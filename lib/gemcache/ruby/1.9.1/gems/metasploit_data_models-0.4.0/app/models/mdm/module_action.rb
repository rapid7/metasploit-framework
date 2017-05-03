class Mdm::ModuleAction < ActiveRecord::Base
  self.table_name = 'module_actions'

  #
  # Relations
  #

  belongs_to :module_detail, :class_name => 'Mdm::ModuleDetail'

  #
  # Validations
  #
  validate :name, :presence => true

  ActiveSupport.run_load_hooks(:mdm_module_action, self)
end
