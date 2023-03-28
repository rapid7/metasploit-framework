require 'active_model'

# class IsAnArray < ActiveModel::Validator
#   def validate(mod)
#     unless mod.author.is_a?(Array)
#       mod.errors.add :author, 'must be an array'
#     end
#   end
# end

class ModuleValidator < SimpleDelegator
  include ActiveModel::Validations

  attr_reader :mod

  def initialize(mod)
    super
    @mod = mod
  end

  #
  # Acceptable Stability ratings
  #
  valid_stability_values = [
    Msf::CRASH_SAFE,
    Msf::CRASH_SERVICE_RESTARTS,
    Msf::CRASH_SERVICE_DOWN,
    Msf::CRASH_OS_RESTARTS,
    Msf::CRASH_OS_DOWN,
    Msf::SERVICE_RESOURCE_LOSS,
    Msf::OS_RESOURCE_LOSS
  ]

  #
  # Acceptable Side-effect ratings
  #
  valid_side_effect_values = [
    Msf::ARTIFACTS_ON_DISK,
    Msf::CONFIG_CHANGES,
    Msf::IOC_IN_LOGS,
    Msf::ACCOUNT_LOCKOUTS,
    Msf::SCREEN_EFFECTS,
    Msf::AUDIO_EFFECTS,
    Msf::PHYSICAL_EFFECTS
  ]

  #
  # Acceptable Reliability ratings
  #
  valid_reliability_values = [
    Msf::FIRST_ATTEMPT_FAIL,
    Msf::REPEATABLE_SESSION,
    Msf::UNRELIABLE_SESSION
  ]

  #
  # Acceptable site references
  #
  valid_ctx_id_values = [
    'CVE',
    'CWE',
    'BID',
    # milw0rm references are no longer supported.
    # 'MIL',
    'MSB',
    'EDB',
    'US-CERT-VU',
    'ZDI',
    'URL',
    'WPVDB',
    'PACKETSTORM',
    'LOGO',
    'SOUNDTRACK',
    'OSVDB',
    # Issued by Veritas
    'VTS',
    # Openwall - https://www.openwall.com/ove/
    'OVE'
  ]

  def validate_excellent_ranking
    if rank_to_s == 'excellent' && !stability.include?('crash-safe')
      errors.add :stability, 'module must have CRASH_SAFE stability value if module has an ExcellentRanking'
    end
  end

  def validate_authors
    unless author.is_a?(Array)
      errors.add :author, 'module authors must be an array'
    end
  end

  def validate_references
    unless references.is_a?(Array)
      errors.add :references, 'module references must be an array'
    end
  end

  def validate_description
    unless description.is_a?(String)
      errors.add :description, 'module description must be a string'
    end
  end

  def validate_stability
    unless stability.is_a?(Array)
      errors.add :stability, 'module stability must be an array'
    end
  end

  def validate_side_effects
    unless side_effects.is_a?(Array)
      errors.add :side_effects, 'module side effects must be an array'
    end
  end

  def validate_reliability
    unless reliability.is_a?(Array)
      errors.add :reliability, 'module reliability must be an array'
    end
  end

  def requires_author?
    #
    # Module types that require authors
    #
    requires_authors = %w[exploits auxiliary post]
    requires_authors.include?(type)
  end

  def payload?
    type == 'payload'
  end

  def has_notes?
    !notes.empty?
  end

  validates :mod, presence: true

  with_options if: :has_notes? do |mod|
    mod.validates :stability,
                  presence: true,
                  if: :validate_excellent_ranking

    mod.validates :stability,
                  inclusion: { in: valid_stability_values, message: 'must include a valid stability value' },
                  if: :validate_stability

    mod.validates :side_effects,
                  inclusion: { in: valid_side_effect_values, message: 'must include a valid side effect value' },
                  if: :validate_side_effects

    mod.validates :reliability,
                  inclusion: { in: valid_reliability_values, message: 'must include a valid reliability value' },
                  if: :validate_reliability
  end

  validates :references,
            presence: true,
            inclusion: { in: valid_ctx_id_values, message: 'must include a valid reference' },
            if: :validate_references

  validates :license,
            presence: true,
            inclusion: { in: LICENSES, message: 'must include a valid license' }

  validates :rank,
            presence: true,
            inclusion: { in: Msf::RankingName.keys, message: 'must include a valid ranking' }

  # validates :author_to_s, # TODO: Bad error message
  #           format: { with: /\A[^@.]+\z/, message: 'must not include Twitter handles, please. Try leaving it in a comment instead.'}

  validates :author,
            presence: true,
            if: :requires_author? && :validate_authors

  validates :name,
            presence: true,
            format: { with: /\A[^&<>]+\z/, message: 'must not contain the characters ^&<>' }

  validates :file_path,
            presence: true,
            if: -> { file_path.split('/').last.match(/^[a-z0-9]+(?:_[a-z0-9]+)*\.rb$/) }

  validates :description,
            presence: true,
            if: :validate_description,
            unless: :payload?
end

RSpec.shared_examples_for 'a module with valid metadata' do

  # def get_reference_ctx_id
  #   references_ctx_id_list = []
  #   subject.references.each { |ref| references_ctx_id_list << ref.ctx_id }
  #
  #   references_ctx_id_list
  # end

  # let(:mod) do
  #   framework = instance_double(Msf::Framework)
  #   instance_double(
  #     Msf::Exploit,
  #     framework: framework,
  #     name: 'Testing bad chars',
  #     author: ['Foobar'], # TODO: Only exploits, auxiliary and post require authors
  #     license: MSF_LICENSE,
  #     references: ['CVE'], # TODO: Needs to access the keys and compare
  #     rank_to_s: 'excellent',
  #     rank: 600,
  #     notes: {},
  #     stability: ['crash-safe'],
  #     side_effects: ['artifacts-on-disk'],
  #     reliability: ['first-attempt-fail'],
  #     file_path: 'modules/exploits/windows/smb/cve_2020_0796_smbghost.rb',
  #     description: %q{
  #         A vulnerability exists within the Microsoft Server Message Block 3.1.1 (SMBv3) protocol that can be leveraged to
  #         execute code on a vulnerable server. This remove exploit implementation leverages this flaw to execute code
  #         in the context of the kernel, finally yielding a session as NT AUTHORITY\SYSTEM in spoolsv.exe. Exploitation
  #         can take a few minutes as the necessary data is gathered.
  #       }
  #   )
  # end

  it 'verifies modules metadata' do

    # aggregate_failures do

      # Verify we have a instance of the module
      expect(subject).to_not be_nil

      validator = ModuleValidator.new(subject)

      validator.validate
      # expect(validator).to be_valid
      expect(validator.errors.full_messages).to be_kind_of(Array)
    # end
  end
end
