# Origin of `Metasploit::Credential::Core`s that were gathered from a {#service} by a
# {#module_full_name auxiliary or exploit module}.  Contrast with {Metasploit::Credential::Origin::Session} which is
# for `Metasploit::Credential::Core`s derived after a {Metasploit::Credential::Origin::Session#session session} is
# gained and a {Metasploit::Credential::Origin::Session#post_reference_name post module} is run from the session to
# gather credentials.
class Metasploit::Credential::Origin::Service < ActiveRecord::Base
  #
  # CONSTANTS
  #

  # Regular expression that matches any `Mdm::Module::Detail#fullname` for {#module_full_name} where
  # `Mdm::Module::Detail#mtype` is `'auxiliary'` or `'exploit'` and the remainder is a valid
  # `Mdm::Module::Detail#refname` (it does not contain a `'\'` and is lower case alphanumeric).
  MODULE_FULL_NAME_REGEXP = /\A(?<module_type>auxiliary|exploit|post)\/(?<reference_name>[\-0-9A-Z_a-z]+(?:\/[\-0-9A-Z_a-z]+)*)\Z/

  #
  # Associations
  #

  # @!attribute cores
  #   {Metasploit::Credential::Core Core credentials} imported from {#service} using
  #   {#module_full_name the auxiliary or exploit module}.
  #
  #   @return [ActiveRecord::Relation<Metasploit::Credential::Core>]
  has_many :cores,
           as: :origin,
           class_name: 'Metasploit::Credential::Core',
           dependent: :destroy

  # @!attribute service
  #   The service from which the {#cores core credentials} were gathered.
  #
  #   @return [Mdm::Service]
  belongs_to :service,
             class_name: 'Mdm::Service',
             inverse_of: :credential_origins

  #
  # Attributes
  #

  # @!attribute module_full_name
  #   The `Mdm::Module::Detail#fullname` of the auxiliary or exploit module that accessed {#service}.
  #
  #   @return [String] `'auxiliary/<Mdm::Module::Detail#refname>'` if an auxiliary module was used.
  #   @return [String] `'exploit/<Mdm::Module::Detail#refname>'` if an exploit module was used.

  #
  # Validations
  #

  validates :module_full_name,
            format: {
                with: MODULE_FULL_NAME_REGEXP
            },
            uniqueness: {
                scope: :service_id
            }
  validates :service,
            presence: true

  Metasploit::Concern.run(self)
end
