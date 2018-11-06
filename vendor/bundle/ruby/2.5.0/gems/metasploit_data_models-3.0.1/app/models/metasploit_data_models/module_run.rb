# {MetasploitDataModels::ModuleRun} holds the record of having launched a piece of Metasploit content.
# It has associations to {Mdm::User} for audit purposes, and makes polymorphic associations to things like
# {Mdm::Vuln} and {Mdm::Host} for flexible record keeping about activity attacking either specific vulns or just
# making mischief on specific remote targets w/out the context of a vuln or even a remote IP service.
#
# There are also associations to {Mdm::Session} for two use cases: a `spawned_session` is a
# session created by the ModuleRun. A `target_session` is a session that the ModuleRun
# is acting upon (e.g.) for running a post module.
class MetasploitDataModels::ModuleRun < ActiveRecord::Base
  #
  # Constants
  #

  # Marks the module as having successfully run
  SUCCEED     = 'succeeded'
  # Marks the run as having not run successfully
  FAIL        = 'failed'
  # Marks the module as having had a runtime error
  ERROR       = 'error'
  # {ModuleRun} objects will be validated against these statuses
  VALID_STATUSES = [SUCCEED, FAIL, ERROR]


  #
  # Attributes
  #

  # @!attribute [rw] attempted_at
  #   The date/time when this module was run
  #   @return [Datetime]

  # @!attribute [rw] fail_detail
  #   Arbitrary information captured by the module to give in-depth reason for failure
  #   @return [String]

  # @!attribute [rw] fail_reason
  #   One of the values of the constants in `Msf::Module::Failure`
  #   @return [String]

  # @!attribute [rw] module_name
  #   The Msf::Module#fullname of the module being run
  #   @return [String]

  # @!attribute [rw] port
  #   The port that the remote host was attacked on, if any
  #   @return [Fixnum]

  # @!attribute [rw] proto
  #   The name of the protocol that the host was attacked on, if any
  #   @return [String]

  # @!attribute [rw] session_id
  #   The {Mdm::Session} that this was run with, in the case of a post module. In exploit modules, this field will
  #   remain null.
  #   @return [Datetime]

  # @!attribute [rw] status
  #   The result of running the module
  #   @return [String]

  # @!attribute [rw] username
  #   The name of the user running this module
  #   @return [String]



  #
  # Associations
  #



  # @!attribute [rw] loots
  #  The sweet, sweet loot taken by this module_run
  #
  #  @return [ActiveRecord::Relation<Mdm::Loot>]
  has_many :loots,
           class_name: 'Mdm::Loot',
           inverse_of: :module_run

  # @!attribute [rw] module_detail
  #  The cached module information
  #
  #  @return [ActiveRecord::Relation<Mdm::Module::Detail>]
  belongs_to :module_detail,
             class_name: 'Mdm::Module::Detail',
             inverse_of: :module_runs,
             foreign_key: :module_fullname,
             primary_key: :fullname

  # @!attribute [rw] spawned_session
  #
  #  The session created by running this module.
  #  Note that this is NOT the session that modules are run on.
  #
  #  @return [Mdm::Session]
  has_one :spawned_session,
             class_name: 'Mdm::Session',
             inverse_of: :originating_module_run


  # @!attribute [rw] target_session
  #
  #  The session this module was run on, if any.
  #  Note that this is NOT a session created by this module run
  #  of exploit modules.
  #
  #  @return [Mdm::Session]
  belongs_to :target_session,
             class_name: 'Mdm::Session',
             foreign_key: :session_id,
             inverse_of: :target_module_runs



  # @!attribute [rw] trackable
  #
  #  A polymorphic association that is tracked as being related to this module run.
  #  {Mdm::Host} and {Mdm::Vuln} can each have {ModuleRun} objects.
  #
  #  @return [Mdm::Host, Mdm::Vuln]
  belongs_to :trackable, polymorphic: true


  # @!attribute [rw] user
  #
  #  The user that launched this module
  #
  #  @return [Mdm::User]
  belongs_to :user,
             class_name:  'Mdm::User',
             foreign_key: 'user_id',
             inverse_of: :module_runs



  #
  #
  # Validations
  #
  #

  #
  # Method Validations
  #


  # spawned_session is only valid for *exploit modules*
  validate :no_spawned_session_for_non_exploits_except_logins

  # target_session is only valid for *non-exploit modules*
  validate :no_target_session_for_exploits

  # Can't save without information on what module has run
  validate :module_information_is_present

  #
  # Attribute Validations
  #

  # When the module was run
  validates :attempted_at,
            presence: true
  # Result of running the module
  validates :status,
            inclusion: VALID_STATUSES

  # Splits strings formatted like Msf::Module#fullname into components
  #
  # @example
  #   module_name = "exploit/windows/multi/mah-rad-exploit"
  #   module_name_components  # => ["exploit","windows","multi","mah-rad-exploit"]
  # @return [Array]
  def module_name_components
    module_fullname.split('/')
  end

  private

  # Mark the object as invalid if there is no associated #module_name or {Mdm::ModuleDetail}
  # @return [void]
  def module_information_is_present
    if module_fullname.blank?
      errors.add(:base, "module_fullname cannot be blank")
    end
  end

  # Mark the object as invalid if there is a spawned_session but the module is *not* an exploit
  # and not an aux module with the word "login" in the final portion of `module_fullname`
  #
  # @return [void]
  def no_spawned_session_for_non_exploits_except_logins
    return true unless spawned_session.present?
    return true if module_name_components.last.include?("login")

    if module_name_components.first != 'exploit'
      errors.add(:base, 'spawned_session cannot be set for non-exploit modules. Use target_session.')
    end
  end

  # Mark the object as invalid if there is a target_session but the module is an exploit
  # @return [void]
  def no_target_session_for_exploits
    return true unless target_session.present? # nothing to do unless target_session is set

    if module_name_components.first == 'exploit'
      return true if module_name_components[2] == 'local'
      errors.add(:base, 'target_session cannot be set for exploit modules. Use spawned_session.')
    end
  end


end
