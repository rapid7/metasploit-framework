# An external vulnerability reference for vulnerabilities that aren't part of a module.  {Mdm::Module::Ref} should be
# used whenever possible and Mdm::Ref should only be used when the vulnerability is from an import and can't be
# correlated to a module and its {Mdm::Module::Detail}.
class Mdm::Ref < ActiveRecord::Base
  #
  # Associations
  #

  # @!attribute [r] module_refs
  #   {Mdm::Module::Ref Mdm::Module::Refs} with the same name as this ref.
  #
  #   @return [Array<Mdm::Module::Ref>]
  has_many :module_refs,
           :class_name => 'Mdm::Module::Ref',
           :foreign_key => :name,
           :primary_key => :name

  # @!attribute [rw] vulns_refs
  #   Join model to {Mdm::Vuln Mdm::Vulns}.  Use {#vulns} to get the actual {Mdm::Vuln Mdm::Vulns}.
  #
  #   @todo MSP-3066
  #   @return [Array<Mdm::VulnRef>]
  has_many :vulns_refs,
           :class_name => 'Mdm::VulnRef',
           inverse_of: :ref

  #
  # Through :vuln_refs
  #

  # @!attribute [rw] vulns
  #   Vulnerabilities referenced by this reference.
  #
  #   @return [Array<Mdm::Vuln>]
  has_many :vulns, :class_name => 'Mdm::Vuln', :through => :vulns_refs

  #
  # Attributes
  #

  # @!attribute [rw] name
  #   Designation for external reference.  May include a prefix for the authority, such as 'CVE-', in which case the
  #   rest of the name is the designation assigned by that authority.
  #
  #   @return [String]

  Metasploit::Concern.run(self)
end
