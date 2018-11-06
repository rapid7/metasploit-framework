# A potential target for a {Mdm::Module::Detail exploit Metasploit Module}.  Targets can change options including
# offsets for ROP chains to tune an exploit to work with different system libraries and versions.
class Mdm::Module::Target < ActiveRecord::Base
  self.table_name = 'module_targets'

  #
  # Associations
  #

  # Exploit Metasploit Module with the {#name named} target at the given {#index}.
  belongs_to :detail, :class_name => 'Mdm::Module::Detail'

  #
  # Attributes
  #

  # @!attribute index
  #   The index of this target in the {#detail exploit Metasploit Module}'s list of targets. The index is used for
  #   target selection.
  #
  #   @return [Integer]

  # @!attribute name
  #   The name of this target.
  #
  #   @return [String]

  #
  # Validators
  #

  validates :detail, :presence => true
  validates :index, :presence => true
  validates :name, :presence => true

  Metasploit::Concern.run(self)
end
