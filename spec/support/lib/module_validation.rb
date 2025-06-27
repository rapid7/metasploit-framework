require 'active_model'

module ModuleValidation
  # Checks if values within arrays included within the passed list of acceptable values
  class ArrayInclusionValidator < ActiveModel::EachValidator
    def validate_each(record, attribute, value)
      unless value.is_a?(Array)
        record.errors.add(attribute, "#{attribute} must be an array")
        return
      end

      # Special cases for modules/exploits/bsd/finger/morris_fingerd_bof.rb which has a one-off architecture defined in
      # the module itself, and that value is not included in the valid list of architectures.
      # https://github.com/rapid7/metasploit-framework/blob/389d84cbf0d7c58727846466d9a9f6a468f32c61/modules/exploits/bsd/finger/morris_fingerd_bof.rb#L11
      return if attribute == :arch && value == ["vax"] && record.fullname == "exploit/bsd/finger/morris_fingerd_bof"
      return if value == options[:sentinel_value]

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
    validate :validate_description_does_not_contain_non_printable_chars
    validate :validate_name_does_not_contain_non_printable_chars
    validate :validate_attack_reference_format

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
      ATT&CK
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
        return if stability == Msf::UNKNOWN_STABILITY

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

    def validate_attack_reference_format
      references.each do |ref|
        next unless ref.respond_to?(:ctx_id) && ref.respond_to?(:ctx_val)
        next unless ref.ctx_id == 'ATT&CK'

        val = ref.ctx_val
        prefix = val[/\A[A-Z]+/]
        valid_format = Msf::Mitre::Attack::Categories::PATHS.key?(prefix) && val.match?(/\A#{prefix}[\d.]+\z/)
        whitespace = val.match?(/\s/)

        unless valid_format && !whitespace
          errors.add :references, "ATT&CK reference '#{val}' is invalid. Must start with one of #{Msf::Mitre::Attack::Categories::PATHS.keys.inspect} and be followed by digits/periods, no whitespace."
        end
      end
    end

    def has_notes?
      !notes.empty?
    end

    def validate_description_does_not_contain_non_printable_chars
      unless description&.match?(/\A[ -~\t\n]*\z/)
        # Blank descriptions are validated elsewhere, so we will return early to not also add this error
        # and cause unnecessary confusion.
        return if description.nil?

        errors.add :description, 'must only contain human-readable printable ascii characters, including newlines and tabs'
      end
    end

    def validate_name_does_not_contain_non_printable_chars
      unless name&.match?(/\A[ -~]+\z/)
        errors.add :name, 'must only contain human-readable printable ascii characters'
      end
    end

    validates :mod, presence: true

    with_options if: :has_notes? do |mod|
      mod.validate :validate_crash_safe_not_present_in_stability_notes
      mod.validate :validate_notes_values_are_arrays

      mod.validates :stability,
                    'module_validation/array_inclusion': { in: VALID_STABILITY_VALUES, sentinel_value: Msf::UNKNOWN_STABILITY }

      mod.validates :side_effects,
                    'module_validation/array_inclusion': { in: VALID_SIDE_EFFECT_VALUES, sentinel_value: Msf::UNKNOWN_SIDE_EFFECTS }

      mod.validates :reliability,
                    'module_validation/array_inclusion': { in: VALID_RELIABILITY_VALUES, sentinel_value: Msf::UNKNOWN_RELIABILITY }
    end

    validates :arch,
              'module_validation/array_inclusion': { in: Rex::Arch::ARCH_TYPES }

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
