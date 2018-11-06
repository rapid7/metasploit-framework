# A supported architecture for a given {Mdm::Module::Detail Metasploit Module}
class Mdm::Module::Arch < ActiveRecord::Base
  self.table_name = 'module_archs'

  #
  # Associations
  #

  belongs_to :detail, :class_name => 'Mdm::Module::Detail'

  #
  # Attributes
  #

  # @!attribute name
  #   The architecture abbreviation, such as `'x86'`
  #
  #   @return [String]

  #
  # Validations
  #

  validates :detail, :presence => true
  validates :name, :presence => true

  Metasploit::Concern.run(self)
end
