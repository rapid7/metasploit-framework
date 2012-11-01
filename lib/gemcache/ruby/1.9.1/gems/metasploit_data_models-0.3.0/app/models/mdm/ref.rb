class Mdm::Ref < ActiveRecord::Base
  #
  # Relations
  #

  has_many :vulns_refs, :class_name => 'Mdm::VulnRef'

  #
  # Through :vuln_refs
  #
  has_many :vulns, :class_name => 'Mdm::Vuln', :through => :vulns_refs

  ActiveSupport.run_load_hooks(:mdm_ref, self)
end
