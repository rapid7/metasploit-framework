# {#name Platform} on which the {#detail Metasploit Module} can run.
class Mdm::Module::Platform < ActiveRecord::Base
  self.table_name = 'module_platforms'

  #
  # Associations
  #

  # The Metasploit Module that can run on the {#name named} platform.
  belongs_to :detail, :class_name => 'Mdm::Module::Detail'

  #
  # Attributes
  #

  # @!attribute name
  #   The name of the platform.
  #
  #   @return [String]

  #
  # Validations
  #

  validates :detail, :presence => true
  validates :name, :presence => true

  Metasploit::Concern.run(self)
end
