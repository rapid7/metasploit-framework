class Mdm::Route < ActiveRecord::Base
  #
  # Relations
  #

  belongs_to :session, :class_name => 'Mdm::Session'

  ActiveSupport.run_load_hooks(:mdm_route, self)
end
