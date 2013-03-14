class Mdm::ModulePlatform < ActiveRecord::Base
  self.table_name = 'module_platforms'

  #
  # Relations
  #

  belongs_to :module_detail

  #
  # Validations
  #

  validate :name, :presence => true

  ActiveSupport.run_load_hooks(:mdm_module_platform, self)
end
