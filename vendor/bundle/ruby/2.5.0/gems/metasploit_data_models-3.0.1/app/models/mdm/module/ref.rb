# External references to the vulnerability exploited by this module.
class Mdm::Module::Ref < ActiveRecord::Base
  self.table_name = 'module_refs'

  #
  # Associations
  #

  # @!attribute [rw] detail
  #   The root of the module metadata tree.
  #
  #   @return [Mdm::Module::Detail]
  belongs_to :detail, :class_name => 'Mdm::Module::Detail'

  # @!attribute [r] refs
  #   References with the same name attached to {Mdm::Vuln Mdm::Vulns}.
  #
  #   @return [Array<Mdm::Ref>]
  has_many :refs,
           :class_name => 'Mdm::Ref',
           :foreign_key => :name,
           :primary_key => :name

  #
  # Attributes
  #

  # @!attribute [rw] name
  #   Designation for external reference.  May include a prefix for the authority, such as 'CVE-', in which case the
  #   rest of the name is the designation assigned by that authority.
  #
  #   @return [String]

  #
  # Validations
  #

  validates :detail, :presence => true
  validates :name, :presence => true

  Metasploit::Concern.run(self)
end
