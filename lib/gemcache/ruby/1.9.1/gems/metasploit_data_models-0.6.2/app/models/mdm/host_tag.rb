class Mdm::HostTag < ActiveRecord::Base
  self.table_name = "hosts_tags"

  #
  # Relations
  #

  belongs_to :host, :class_name => 'Mdm::Host'
  belongs_to :tag, :class_name => 'Mdm::Tag'

  ActiveSupport.run_load_hooks(:mdm_host_tag, self)
end

