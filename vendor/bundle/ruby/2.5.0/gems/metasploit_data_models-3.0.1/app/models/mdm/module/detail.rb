# Details about an Msf::Module.  Metadata that can be an array is stored in associations in modules under the
# {Mdm::Module} namespace.
class Mdm::Module::Detail < ActiveRecord::Base
  self.table_name = 'module_details'

  #
  # CONSTANTS
  #

  # The directory for a given {#mtype} is a not always the pluralization of {#mtype}, so this maps the {#mtype} to the
  # type directory that is used to generate the {#file} from the {#mtype} and {#refname}.
  DIRECTORY_BY_TYPE = {
      'auxiliary' => 'auxiliary',
      'encoder' => 'encoders',
      'exploit' => 'exploits',
      'nop' => 'nops',
      'payload' => 'payloads',
      'post' => 'post',
      'evasion' => 'evasion'
  }

  # {#privileged} is Boolean so, valid values are just `true` and `false`, but since both the validation and
  # factory need an array of valid values, this constant exists.
  PRIVILEGES = [
      false,
      true
  ]

  # Converts {#rank}, which is an Integer, to the name used for that rank.
  RANK_BY_NAME = {
      'Manual' => 0,
      'Low' => 100,
      'Average' => 200,
      'Normal' => 300,
      'Good' => 400,
      'Great' => 500,
      'Excellent' => 600
  }

  # Valid values for {#stance}.
  STANCES = [
      'aggressive',
      'passive'
  ]

  #
  # Associations
  #

  # @!attribute [rw] actions
  #   Auxiliary actions to perform when this running this module.
  #
  #   @return [ActiveRecord::Relation<Mdm::Module::Action>]
  has_many :actions,   :class_name => 'Mdm::Module::Action',   :dependent => :destroy

  # @!attribute [rw] archs
  #   Architectures supported by this module.
  #
  #   @return [ActiveRecord::Relation<Mdm::Module::Arch>]
  has_many :archs,     :class_name => 'Mdm::Module::Arch',     :dependent => :destroy

  # @!attribute [rw] authors
  #   Authors (and their emails) of this module.  Usually includes the original discoverer who wrote the
  #   proof-of-concept and then the people that ported the proof-of-concept to metasploit-framework.
  #
  #   @return [ActiveRecord::Relation<Mdm::Module::Mixin>]
  has_many :authors,   :class_name => 'Mdm::Module::Author',   :dependent => :destroy

  # @!attribute [rw] matches
  #   Matches for this module
  #
  #   @return [ActiveRecord::Relation<MetasploitDataModels::AutomaticExploitation::Match>]
  has_many :matches,
           :class_name => 'MetasploitDataModels::AutomaticExploitation::Match',
           :primary_key => :fullname,
           :foreign_key => :module_fullname,
           :inverse_of => :module_detail

  # @!attribute [rw] mixins
  #   Mixins used by this module.
  #
  #   @return [ActiveRecord::Relation<Mdm::Module::Mixin>]
  has_many :mixins,    :class_name => 'Mdm::Module::Mixin',    :dependent => :destroy

  # @!attribute [rw] module_runs
  #   Records of times when this module has been used
  #
  #   @return [ActiveRecord::Relation<MetasploitDataModels::ModuleRun>]
  has_many :module_runs,
           :class_name => 'MetasploitDataModels::ModuleRun',
           :primary_key => :fullname,
           :foreign_key => :module_fullname,
           :inverse_of => :module_detail

  # @!attribute [rw] platforms
  #   Platforms supported by this module.
  #
  #   @return [ActiveRecord::Relation<Mdm::Module::Platform>]
  has_many :platforms, :class_name => 'Mdm::Module::Platform', :dependent => :destroy

  # @!attribute [rw] refs
  #   External references to the vulnerabilities this module exploits.
  #
  #   @return [ActiveRecord::Relation<Mdm::Module::Ref>]
  has_many :refs,      :class_name => 'Mdm::Module::Ref',      :dependent => :destroy

  # @!attribute [rw] targets
  #   Names of targets with different configurations that can be exploited by this module.
  #
  #   @return [ActiveRecord::Relation<Mdm::Module::Target>]
  has_many :targets,   :class_name => 'Mdm::Module::Target',   :dependent => :destroy

  #
  # Attributes
  #

  # @!attribute [rw] default_action
  #   Name of the default action in {#actions}.
  #
  #   @return [String] {Mdm::Module::Action#name}.

  # @!attribute [rw] default_target
  #   Name of the default target in {#targets}.
  #
  #   @return [String] {Mdm::Module::Target#name}.

  # @!attribute [rw] description
  #   A long, paragraph description of what the module does.
  #
  #   @return [String]

  # @!attribute [rw] disclosure_date
  #   The date the vulnerability exploited by this module was disclosed to the public.
  #
  #   @return [DateTime]

  # @!attribute [rw] file
  #   The full path to the module file on-disk.
  #
  #   @return [String]

  # @!attribute [rw] fullname
  #   The full name of the module.  The full name is "{#mtype}/{#refname}".
  #
  #   @return [String]

  # @!attribute [rw] license
  #   The name of the software license for the module's code.
  #
  #   @return [String]

  # @!attribute [rw] mtime
  #   The modification time of the module file on-disk.
  #
  #   @return [DateTime]

  # @!attribute [rw] mtype
  #   The type of the module.
  #
  #   @return [String] key in {DIRECTORY_BY_TYPE}

  # @!attribute [rw] name
  #   The human readable name of the module.  It is unrelated to {#fullname} or {#refname} and is better thought of
  #   as a short summary of the {#description}.
  #
  #   @return [String]

  # @!attribute [rw] privileged
  #   Whether this module requires priveleged access to run.
  #
  #   @return [Boolean]

  # @!attribute [rw] rank
  #   The reliability of the module and likelyhood that the module won't knock over the service or host being exploited.
  #   Bigger values is better.
  #
  #   @return [Integer]

  # @!attribute [rw] ready
  #   Boolean indicating whether the metadata for the module has been updated from the on-disk module.
  #
  #   @return [false] if the associations are still being updated.
  #   @return [true] if this detail and its associations are up-to-date.

  # @!attribute [rw] refname
  #   The reference name of the module.
  #
  #   @return [String]

  # @!attribute [rw] stance
  #   Whether the module is active or passive.  `nil` if the {#mtype module type} does not
  #   {#supports_stance? support stances}.
  #
  #   @return ['active', 'passive', nil]

  #
  # Scopes
  #

  scope :module_arch, ->(values) {
    joins(Mdm::Module::Detail.join_association(:archs,Arel::Nodes::OuterJoin)).
    where(Mdm::Module::Arch[:name].matches_any(values))
  }

  scope :module_author, ->(values) {
    joins(Mdm::Module::Detail.join_association(:authors, Arel::Nodes::OuterJoin)).
    where(
      Mdm::Module::Author[:email].matches_any(values).or(
        Mdm::Module::Author[:name].matches_any(values)
      )
    )
  }

  scope :module_name, ->(values) {
    where(
      Mdm::Module::Detail[:fullname].matches_any(values).or(
        Mdm::Module::Detail[:name].matches_any(values)
      )
    )
  }

  scope :module_os_or_platform, ->(values) {
    joins(
      Mdm::Module::Detail.join_association(:platforms, Arel::Nodes::OuterJoin),
      Mdm::Module::Detail.join_association(:targets, Arel::Nodes::OuterJoin)
    ).where(
      Mdm::Module::Platform[:name].matches_any(values).or(
        Mdm::Module::Target[:name].matches_any(values)
      )
    )
  }

  scope :module_ref, ->(values) {
    joins(Mdm::Module::Detail.join_association(:refs, Arel::Nodes::OuterJoin)).
    where(Mdm::Module::Ref[:name].matches_any(values))
  }

  scope :module_stance, ->(values) { where(Mdm::Module::Detail[:stance].matches_any(values)) }

  scope :module_text, ->(values) {
    joins(
      Mdm::Module::Detail.join_association(:actions,    Arel::Nodes::OuterJoin),
      Mdm::Module::Detail.join_association(:archs,      Arel::Nodes::OuterJoin),
      Mdm::Module::Detail.join_association(:authors,    Arel::Nodes::OuterJoin),
      Mdm::Module::Detail.join_association(:platforms,  Arel::Nodes::OuterJoin),
      Mdm::Module::Detail.join_association(:refs,       Arel::Nodes::OuterJoin),
      Mdm::Module::Detail.join_association(:targets,    Arel::Nodes::OuterJoin)
    ).where(
      Mdm::Module::Detail[:description].matches_any(values).or(
      Mdm::Module::Detail[:fullname].matches_any(values).or(
      Mdm::Module::Detail[:name].matches_any(values).or(
      Mdm::Module::Action[:name].matches_any(values).or(
      Mdm::Module::Arch[:name].matches_any(values).or(
      Mdm::Module::Author[:name].matches_any(values).or(
      Mdm::Module::Platform[:name].matches_any(values).or(
      Mdm::Module::Ref[:name].matches_any(values).or(
      Mdm::Module::Target[:name].matches_any(values)
    )))))))))
  }


  scope :module_type, ->(values) { where(Mdm::Module::Detail[:mtype].matches_any(values)) }

  #
  # Validations
  #

  validates :mtype,
            :inclusion => {
                :in => DIRECTORY_BY_TYPE.keys
            }
  validates :privileged,
            :inclusion => {
                :in => PRIVILEGES
            }
  validates :rank,
            :inclusion => {
                :in => RANK_BY_NAME.values
            },
            :numericality => {
                :only_integer => true
            }
  validates :refname, :presence => true
  validates :stance,
            :inclusion => {
                :if => :supports_stance?,
                :in => STANCES
            }

  validates_associated :actions
  validates_associated :archs
  validates_associated :authors
  validates_associated :mixins
  validates_associated :platforms
  validates_associated :refs
  validates_associated :targets

  # Adds an {Mdm::Module::Action} with the given {Mdm::Module::Action#name} to {#actions} and immediately saves it to
  # the database.
  #
  # @param name [String] {Mdm::Module::Action#name}.
  # @return [true] if save was successful.
  # @return [false] if save was unsucessful.
  def add_action(name)
    self.actions.build(:name => name).save
  end

  # Adds an {Mdm::Module::Arch} with the given {Mdm::Module::Arch#name} to {#archs} and immediately saves it to the
  # database.
  #
  # @param name [String] {Mdm::Module::Arch#name}.
  # @return [true] if save was successful.
  # @return [false] if save was unsuccessful.
  def add_arch(name)
    self.archs.build(:name => name).save
  end

  # Adds an {Mdm::Module::Author} with the given {Mdm::Module::Author#name} and {Mdm::Module::Author#email} to
  # {#authors} and immediately saves it to the database.
  #
  # @param name [String] {Mdm::Module::Author#name}.
  # @param email [String] {Mdm::Module::Author#email}.
  # @return [true] if save was successful.
  # @return [false] if save was unsuccessful.
  def add_author(name, email=nil)
    self.authors.build(:name => name, :email => email).save
  end

  # Adds an {Mdm::Module::Mixin} with the given {Mdm::Module::Mixin#name} to {#mixins} and immediately saves it to the
  # database.
  #
  # @param name [String] {Mdm::Module::Mixin#name}.
  # @return [true] if save was successful.
  # @return [false] if save was unsuccessful.
  def add_mixin(name)
    self.mixins.build(:name => name).save
  end

  # Adds an {Mdm::Module::Platform} with the given {Mdm::Module::Platform#name} to {#platforms} and immediately saves it
  # to the database.
  #
  # @param name [String] {Mdm::Module::Platform#name}.
  # @return [true] if save was successful.
  # @return [false] if save was unsuccessful.
  def add_platform(name)
    self.platforms.build(:name => name).save
  end

  # Adds an {Mdm::Module::Ref} with the given {Mdm::Module::Ref#name} to {#refs} and immediately saves it to the
  # database.
  #
  # @param name [String] {Mdm::Module::Ref#name}.
  # @return [true] if save was successful.
  # @return [false] if save was unsuccessful.
  def add_ref(name)
    self.refs.build(:name => name).save
  end

  # Adds an {Mdm::Module::Target} with the given {Mdm::Module::Target#index} and {Mdm::Module::Target#name} to
  # {#targets} and immediately saves it to the database.
  #
  # @param index [Integer] index of target among other {#targets}.
  # @param name [String] {Mdm::Module::Target#name}.
  # @return [true] if save was successful.
  # @return [false] if save was unsuccessful.
  def add_target(index, name)
    self.targets.build(:index => index, :name => name).save
  end

  # Returns whether this module supports a {#stance}.  Only modules with {#mtype} `'auxiliary'` and `'exploit'` support
  # a non-nil {#stance}.
  #
  # @return [true] if {#mtype} is `'auxiliary'` or `'exploit'`
  # @return [false] otherwise
  # @see https://github.com/rapid7/metasploit-framework/blob/a6070f8584ad9e48918b18c7e765d85f549cb7fd/lib/msf/core/db_manager.rb#L423
  # @see https://github.com/rapid7/metasploit-framework/blob/a6070f8584ad9e48918b18c7e765d85f549cb7fd/lib/msf/core/db_manager.rb#L436
  def supports_stance?
    supports_stance = false

    if ['auxiliary', 'exploit'].include? mtype
      supports_stance = true
    end

    supports_stance
  end

  Metasploit::Concern.run(self)
end
