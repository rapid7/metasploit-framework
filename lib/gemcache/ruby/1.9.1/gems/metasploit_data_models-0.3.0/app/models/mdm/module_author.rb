class Mdm::ModuleAuthor < ActiveRecord::Base
  self.table_name = 'module_authors'

  #
  # Relations
  #

  belongs_to :module_detail

  #
  # Validations
  #

  validate :name, :presence => true

  ActiveSupport.run_load_hooks(:mdm_module_author, self)
end
