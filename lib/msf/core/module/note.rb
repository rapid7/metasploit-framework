# -*- coding: binary -*-

module Msf

  ###
  #
  # Some modules require an extra annotation to provide extra information useful when searching or referencing.
  # The NotesContainer holds various Note objects that might pertain to an alias name (AKA), an explanation as
  # to why a module lacks a CVE (NOCVE), or other data.
  #
  ###

  class NoteContainer < Hash

    def initialize(opts = {})

      opts.each do |note_type, note|
        case note_type
        when 'AKA'
          self.aka = Module::Aka.new(note)
        when 'NOCVE'
          self.nocve = Module::NoCve.new(note)
        end
      end

    end

    def transform
      attrs = {}
      self.instance_variables.each do | a |
        attr = instance_variable_get(a)
        if attr.is_a?(Module::Note)
          attrs[attr.type] = attr.value
        end
      end
      Rex::Transformer.transform(attrs, Array, [ Hash ], 'Notes').first
    end

    #
    # Alias names (also-known-as) for the module
    #
    attr_reader :aka

    #
    # A description explaining why a module lacks a CVE, if applicable
    #
    attr_reader :nocve

  protected

    attr_writer :aka, :nocve

  end



  class Module::Note

    def initialize(type, value)
      @type = type
      @value = value
    end

    attr_reader :type, :value

  end


  class Module::Aka < Module::Note

    def initialize(value)
      super('AKA', value)
    end

  end


  class Module::NoCve < Module::Note

    def initialize(value)
      super('NOCVE', value)
    end

  end

end
