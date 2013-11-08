# Methods dealing with the architectures supports by a module.
module Msf::Module::Architectures
  # @deprecated Use {#architecture_abbreviations} instead.
  # @return (see #architecture_abbreviations)
  def arch
    ActiveSupport::Deprecation.warn "#{self.class}##{__method__} is deprecated.  Use #{self.class}#architecture_abbreviations instead"
    architecture_abbreviations
  end

  # @deprecated Use {#compatible_architecture_abbreviation?} instead.
  # @param (see #compatible_architecture_abbreviation?)
  # @return (see #compatible_architecture_abbreviation?)
  def arch?(architecture_abbreviation)
    ActiveSupport::Deprecation.warn "#{self.class}##{__method__} is deprecated.  Use #{self.class}#compatible_architecture_abbreviation? instead"
    compatible_architecture_abbreviation?(architecture_abbreviation)
  end

  # Abbreviations for architectures on which this module can run.
  #
  # @return [Array<String>] Array of `Metasploit::Model::Architecture#abbreviation`s
  def architecture_abbreviations
    unless instance_variable_defined? :@architecture_abbreviations
      arch = module_info['Arch']

      unless arch
        ActiveSupport::Deprecation.warn(
            "Defaulting to ARCH_X86 when no 'Arch' is given is deprecated.  " \
          "Add explicit `'Arch' => ARCH_X86` to info Hash for #{self.class.module_class.full_name}"
        )
        arch = ARCH_X86
      end

      @architecture_abbreviations = Rex::Transformer.transform(
          arch,
          Array,
          [
              String
          ],
          'Arch'
      )
    end

    @architecture_abbreviations

  end

  attr_writer :architecture_abbreviations

  # Comma separated list of supported architecture abbreviations.
  #
  # @return [String]
  def architecture_abbreviations_to_s
    architecture_abbreviations.join(', ')
  end

  # @deprecated Use {#architecture_abbreviations_to_s} instead.
  # @return (see #architecture_abbreviations_to_s)
  def arch_to_s
    ActiveSupport::Deprecation.warn "#{self.class}##{__method__} is deprecated.  Use #{self}#architecture_abbreviations_to_s instead"
    architecture_abbreviations_to_s
  end

  # Whether the given `architecture_abbreviation` is supported by this module.
  #
  # @param architecture_abbreviation [ARCH_ANY, String] Either ARCH_ANY to match all architectures, or a
  #   `Metasploit::Model::Architecture#abbreviation`.
  # @return [true] if `what` is `ARCH_ANY`.
  # @return [true] if `what` is in {#architecture_abbreviations}.
  # @return [false] if `what` is not in {#architecture_abbreviations}.
  def compatible_architecture_abbreviation?(architecture_abbreviation)
    if architecture_abbreviation == ARCH_ANY
      true
    else
      architecture_abbreviations.include? architecture_abbreviation
    end
  end

  # @deprecated Use `{#architecture_abbreviations}.each` instead.
  # @yield [architecture_abbreviation] Abbreviation for each supported architecture.
  # @yieldparam architecture_abbreviation [String] `Metasploit::Model::Module::Architecture#abbreviation`.
  # @yieldreturn [void]
  # @return [void]
  def each_arch(&block)
    ActiveSupport::Deprecation.warn "#{self.class}##{__method__} is deprecated.  Use #{self}#each_architecture_abbreviation instead"
    architecture_abbreviations.each(&block)
  end
end