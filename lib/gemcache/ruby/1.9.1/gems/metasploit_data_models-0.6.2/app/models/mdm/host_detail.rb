class Mdm::HostDetail < ActiveRecord::Base
  #
  # Relations
  #

  belongs_to :host, :class_name => 'Mdm::Host', :counter_cache => :host_detail_count

  #
  # Validations
  #

  validates :host_id, :presence => true

  ActiveSupport.run_load_hooks(:mdm_host_detail, self)
end
