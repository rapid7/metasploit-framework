class Mdm::Client < ActiveRecord::Base
  #
  # Relations
  #
  belongs_to :campaign, :class_name => 'Mdm::Campaign'
  belongs_to :host, :class_name => 'Mdm::Host'

  ActiveSupport.run_load_hooks(:mdm_client, self)
end
