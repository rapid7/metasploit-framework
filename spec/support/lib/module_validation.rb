require 'active_model'

module ModuleValidation
  # Checks if values within arrays included within the passed list of acceptable values
  class ArrayInclusionValidator < ActiveModel::EachValidator
    def validate_each(record, attribute, value)
      unless value.is_a?(Array)
        record.errors.add(attribute, "#{attribute} must be an array")
        return
      end

      invalid_options = value - options[:in]
      message = "contains invalid values #{invalid_options.inspect} - only #{options[:in].inspect} is allowed"

      if invalid_options.any?
        record.errors.add(attribute, :array_inclusion, message: message, value: value)
      end
    end
  end

  # Validates module metadata
  class Validator < SimpleDelegator
    include ActiveModel::Validations

    validate :validate_filename_is_snake_case
    validate :validate_reference_ctx_id
    validate :validate_author_bad_chars
    validate :validate_target_platforms

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
      Msf::ACCOUNT_LOGOUT,
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
      Msf::UNRELIABLE_SESSION,
      Msf::EVENT_DEPENDENT
    ]

    #
    # Acceptable site references
    #
    VALID_REFERENCE_CTX_ID_VALUES = %w[
      CVE
      CWE
      BID
      MSB
      EDB
      US-CERT-VU
      ZDI
      URL
      WPVDB
      PACKETSTORM
      LOGO
      SOUNDTRACK
      OSVDB
      VTS
      OVE
    ]

    def validate_notes_values_are_arrays
      notes.each do |k, v|
        unless v.is_a?(Array)
          errors.add :notes, "note value #{k.inspect} must be an array, got #{v.inspect}"
        end
      end
    end

    def validate_crash_safe_not_present_in_stability_notes
      if rank == Msf::ExcellentRanking && !stability.include?(Msf::CRASH_SAFE)
        errors.add :stability, "must have CRASH_SAFE value if module has an ExcellentRanking, instead found #{stability.inspect}"
      end
    end

    def validate_filename_is_snake_case
      unless file_path.split('/').last.match?(/^[a-z0-9]+(?:_[a-z0-9]+)*\.rb$/)
        errors.add :file_path, "must be snake case, instead found #{file_path.inspect}"
      end
    end

    def validate_reference_ctx_id
      references_ctx_id_list = references.map(&:ctx_id)
      invalid_references = references_ctx_id_list - VALID_REFERENCE_CTX_ID_VALUES

      invalid_references.each do |ref|
        if ref.casecmp?('NOCVE')
          errors.add :references, "#{ref} please include NOCVE values in the 'notes' section, rather than in 'references'"
        elsif ref.casecmp?('AKA')
          errors.add :references, "#{ref} please include AKA values in the 'notes' section, rather than in 'references'"
        else
          errors.add :references, "#{ref} is not valid, must be in #{VALID_REFERENCE_CTX_ID_VALUES}"
        end
      end
    end

    def validate_author_bad_chars
      author.each do |i|
        if i.name =~ /^@.+$/
          errors.add :author, "must not include username handles, found #{i.name.inspect}. Try leaving it in a comment instead"
        end
      end
    end

    def validate_target_platforms
      if platform.blank? && type == 'exploit'
        targets.each do |target|
          if target.platform.blank?
            errors.add :platform, 'must be included either within targets or platform module metadata'
          end
        end
      end
    end

    def has_notes?
      !notes.empty?
    end

    validates :mod, presence: true

    with_options if: :has_notes? do |mod|
      mod.validate :validate_crash_safe_not_present_in_stability_notes
      mod.validate :validate_notes_values_are_arrays

      mod.validates :stability,
                    'module_validation/array_inclusion': { in: VALID_STABILITY_VALUES }

      mod.validates :side_effects,
                    'module_validation/array_inclusion': { in: VALID_SIDE_EFFECT_VALUES }

      mod.validates :reliability,
                    'module_validation/array_inclusion': { in: VALID_RELIABILITY_VALUES }
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
              format: { with: /\A[^&<>]+\z/, message: 'must not contain the characters &<>' }

    validates :description,
              presence: true
  end
end
