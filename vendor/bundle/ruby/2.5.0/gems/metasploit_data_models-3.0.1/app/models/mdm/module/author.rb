# The {#email} and {#name} of an author of a {#detail Metasploit Module}.
class Mdm::Module::Author < ActiveRecord::Base
  self.table_name = 'module_authors'

  #
  # Associations
  #

  # The authored Metasploit Module.
  belongs_to :detail, :class_name => 'Mdm::Module::Detail'

  #
  # Attributes
  #

  # @!attribute email
  #   The email address of the author.
  #
  #   @return [String]

  # @!attribute name
  #   The name of the author.
  #
  #   @return [String]

  #
  # Validations
  #

  validates :detail, :presence => true
  validates :name, :presence => true

  Metasploit::Concern.run(self)
end
