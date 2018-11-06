# @deprecated Never populated by metasploit-framework.
#
# Module mixed into a {#detail Metasploit Module}.
class Mdm::Module::Mixin < ActiveRecord::Base
  self.table_name = 'module_mixins'

  #
  # Associations
  #

  # Metasploit Module the {#name named} `Module` was mixed in.
  belongs_to :detail, :class_name => 'Mdm::Module::Detail'

  #
  # Attributes
  #

  # @!attribute name
  #   The `Module#name` of the mixed in `Module`.
  #
  #   @return [String]

  #
  # Validation
  #

  validates :detail, :presence => true
  validates :name, :presence => true

  Metasploit::Concern.run(self)
end
