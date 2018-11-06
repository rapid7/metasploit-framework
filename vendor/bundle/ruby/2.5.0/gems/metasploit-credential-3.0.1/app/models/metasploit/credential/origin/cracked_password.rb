# An origin for {#cores core credentials} that were cracked from a {#originating_core core credentials}
class Metasploit::Credential::Origin::CrackedPassword < ActiveRecord::Base

  #
  # Associations
  #

  # @!attribute cores
  #   {Metasploit::Credential::Core Core credentials} derived from cracking {#originating_core}.
  #
  #   @return [ActiveRecord::Relation<Metasploit::Credential::Core>]
  has_many :cores,
           as: :origin,
           class_name: 'Metasploit::Credential::Core',
           dependent: :destroy

  # @!attribute originating_core
  #   The credential that was cracked to get this one.
  #
  #   @return [Metasploit::Credential::Core]
  belongs_to :originating_core,
             class_name: 'Metasploit::Credential::Core',
             foreign_key: 'metasploit_credential_core_id'

  validates :originating_core,
            presence: true

  Metasploit::Concern.run(self)

end
