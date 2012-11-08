class Mdm::ModuleTarget < ActiveRecord::Base
  self.table_name = 'module_targets'

  #
  # Relations
  #

  belongs_to :module_detail

  #
  # Validators
  #

  validate :name, :presence => true

  ActiveSupport.run_load_hooks(:mdm_module_target, self)
end
