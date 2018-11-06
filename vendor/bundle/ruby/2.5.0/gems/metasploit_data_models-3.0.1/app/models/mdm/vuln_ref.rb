# Join model between {Mdm::Vuln} and {Mdm::Ref}.
class Mdm::VulnRef < ActiveRecord::Base
  self.table_name = 'vulns_refs'

  #
  # Associations
  #

  # {Mdm::Ref Reference} to {#vuln}.
  belongs_to :ref,
             class_name: 'Mdm::Ref',
             inverse_of: :vulns_refs

  # {Mdm::Vuln Vulnerability} imported or discovered by metasploit.
  belongs_to :vuln,
             class_name: 'Mdm::Vuln',
             inverse_of: :vulns_refs

  Metasploit::Concern.run(self)
end

