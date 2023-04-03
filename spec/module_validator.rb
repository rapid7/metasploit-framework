require 'active_model'

class ArrayInclusionValidator < ActiveModel::EachValidator
  def validate_each(record, attribute, value)
    unless value.is_a?(Array)
      record.errors.add(attribute, "#{attribute} must be an array")
      return
    end

    if attribute == :references
      reference_keys = []
      value.each { |k, _v| reference_keys << k }
      value = reference_keys
    end

    invalid_options = value - options[:in]
    message = "contains invalid values #{invalid_options.inspect} - only #{options[:in].inspect} is allowed"

    if invalid_options.any?
      record.errors.add(attribute, :array_inclusion, message: message, value: value)
    end
  end
end

class ModuleValidator < SimpleDelegator
  include ActiveModel::Validations

  validate :validate_filename_is_snake_case, :validate_reference_ctx_id, :validate_author_bad_chars

  attr_reader :mod

  def initialize(mod)
    super
    @mod = mod
  end

  #
  # Acceptable Stability ratings
  #
  VALID_STABILITY_VALUES = [
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
  VALID_SIDE_EFFECT_VALUES = [
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
  VALID_RELIABILITY_VALUES = [
    Msf::FIRST_ATTEMPT_FAIL,
    Msf::REPEATABLE_SESSION,
    Msf::UNRELIABLE_SESSION
  ]

  #
  # Acceptable site references
  #
  VALID_REFERENCE_CTX_ID_VALUES = %w[CVE CWE BID MSB EDB US-CERT-VU ZDI URL WPVDB PACKETSTORM LOGO SOUNDTRACK OSVDB VTS OVE]

  def validate_crash_safe_not_present_in_stability_notes
    if rank == Msf::ExcellentRanking && !stability.include?(Msf::CRASH_SAFE)
      errors.add :stability, "must have CRASH_SAFE value if module has an ExcellentRanking, instead found #{stability.inspect}"
    end
  end

  def validate_filename_is_snake_case
    unless file_path.split('/').last.match?(/^[a-z0-9]+(?:_[a-z0-9]+)*\.rb$/)
      errors.add :file_path, 'must be snake case'
    end
  end

  def validate_reference_ctx_id
    references_ctx_id_list = references.map(&:ctx_id)
    invalid_references = references_ctx_id_list - VALID_REFERENCE_CTX_ID_VALUES

    invalid_references.each do |ref|
      errors.add :references, "#{ref} is not valid, must be in #{VALID_REFERENCE_CTX_ID_VALUES}"
    end
  end

  def validate_author_bad_chars
    author.each do |i|
      if i.name =~ /^@.+$/
        errors.add :author, 'must not include Twitter handles, please. Try leaving it in a comment instead.'
      end
    end
  end

  def requires_authors?
    %w[exploit auxiliary post].include?(type)
  end

  def payload?
    type == 'payload'
  end

  def has_notes?
    !notes.empty?
  end

  validates :mod, presence: true

  with_options if: :has_notes? do |mod|

    mod.validate :validate_crash_safe_not_present_in_stability_notes

    mod.validates :stability,
                  array_inclusion: { in: VALID_STABILITY_VALUES }

    mod.validates :side_effects,
                  array_inclusion: { in: VALID_SIDE_EFFECT_VALUES }

    mod.validates :reliability,
                  array_inclusion: { in: VALID_RELIABILITY_VALUES }
  end

  validates :license,
            presence: true,
            inclusion: { in: LICENSES, message: 'must include a valid license' }

  validates :rank,
            presence: true,
            inclusion: { in: Msf::RankingName.keys, message: 'must include a valid module ranking' }

  validates :author,
            presence: true

  validates :name,
            presence: true,
            format: { with: /\A[^&<>]+\z/, message: 'must not contain the characters ^&<>' }

  validates :description,
            presence: true
end
