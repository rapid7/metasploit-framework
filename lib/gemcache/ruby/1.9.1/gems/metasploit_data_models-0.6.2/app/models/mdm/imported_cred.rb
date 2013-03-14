class Mdm::ImportedCred < ActiveRecord::Base
  #
  # Relations
  #

  belongs_to :workspace, :class_name => "Mdm::Workspace"

  ActiveSupport.run_load_hooks(:mdm_imported_cred, self)
end

