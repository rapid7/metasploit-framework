class Mdm::CredFile < ActiveRecord::Base
  #
  # Relations
  #
  belongs_to :workspace, :class_name => 'Mdm::Workspace'

  ActiveSupport.run_load_hooks(:mdm_cred_file, self)
end
