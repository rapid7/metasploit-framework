class Mdm::VulnRef < ActiveRecord::Base
  self.table_name = 'vulns_refs'

  #
  # Relations
  #

  belongs_to :ref, :class_name => 'Mdm::Ref'
  belongs_to :vuln, :class_name => 'Mdm::Vuln'

  ActiveSupport.run_load_hooks(:mdm_vuln_ref, self)
end

