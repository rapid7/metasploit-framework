module Msf::Module::Target::Architectures
  # @deprecated Use {#architecture_abbreviations} instead.
  # @return (see #architecture_abbreviations)
  def arch
    ActiveSupport::Deprecation.warn "#{self.class}##{__method__} is deprecated.  Use #{self.class}#architecture_abbreviations instead"
    architecture_abbreviation
  end

  # Abbreviations for architectures on which this target can run.
  #
  # @return [Array<String>] Array of `Metasploit::Model::Architecture#abbreviation`s.
  def architecture_abbreviations
    declared_architecture_abbreviations || metasploit_instance.architecture_abbreviations
  end

  # The architectures declared for this target in the info hash.  For the actual architectures supported by this target
  # (i.e. when it has no declared architecture and defers to the module's architectures), use
  # {#architecture_abbreviations}.
  #
  # @return [nil] if 'Arch' is not in target {Msf::Module::Target#opts}.
  # @return [Array<String>] Array of `Metasploit::Model::Architecture#abbreviation`s
  def declared_architecture_abbreviations
    unless instance_variable_defined? :@declared_architecture_abbreviations
      raw_architecture_abbreviations = opts['Arch']

      if raw_architecture_abbreviations
        @declared_architecture_abbreviations = Rex::Transformer.transform(
            raw_architecture_abbreviations,
            Array,
            [
                String
            ],
            'Arch'
        )
      else
        # nil to signal to defer to metasploit_instance in {#architecture_abbreviations}
        @declared_architecture_abbreviations = nil
      end
    end

    @declared_architecture_abbreviations
  end
end