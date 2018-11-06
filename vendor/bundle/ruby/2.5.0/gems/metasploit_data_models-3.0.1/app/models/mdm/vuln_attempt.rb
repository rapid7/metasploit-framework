# An attempt to exploit a {#vuln}.
class Mdm::VulnAttempt < ActiveRecord::Base
  
  #
  # Associations
  #

  # Loot gathered from this attempt.
  #
  # @return [Mdm::Loot] if {#exploited} is `true`.
  # @return [nil] if {#exploited} is `false`.
  belongs_to :loot,
             class_name: 'Mdm::Loot',
             inverse_of: :vuln_attempt

  # The session opened by this attempt.
  #
  # @return [Mdm::Session] if {#exploited} is `true`.
  # @return [nil] if {#exploited} is `false`.
  belongs_to :session,
             class_name: 'Mdm::Session',
             inverse_of: :vuln_attempt

  # The {Mdm::Vuln vulnerability} that this attempt was exploiting.
  #
  # @return [Mdm::Vuln]
  belongs_to :vuln,
             class_name: 'Mdm::Vuln',
             counter_cache: :vuln_attempt_count,
             inverse_of: :vuln_attempts

  #
  # Attributes
  #

  # @!attribute attempted_at
  #   When this attempt was made.
  #
  #   @return [DateTime]

  # @!attribute exploited
  #   Whether this attempt was successful.
  #
  #   @return [true] if {#vuln} was exploited.
  #   @return [false] if {#vuln} was not exploited.

  # @!attribute fail_detail
  #   Long details about why this attempt failed.
  #
  #   @return [String] if {#exploited} is `false`.
  #   @return [nil] if {#exploited} is `true`.

  # @!attribute fail_reason
  #   Short reason why this attempt failed.
  #
  #   @return [String] if {#exploited} is `false`.
  #   @return [nil] if {#exploited} is `true`

  # @!attribute module
  #   {Mdm::Module::Detail#fullname Full name of exploit Metasploit Module} that was used in this attempt.
  #
  #   @return [String]

  # @!attribute username
  #   The {Mdm::User#username name of the user} that made this attempt.
  #
  #   @return [String]

  #
  # Validations
  #

  validates :vuln_id, :presence => true

  Metasploit::Concern.run(self)
end
