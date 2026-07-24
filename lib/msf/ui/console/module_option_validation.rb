# -*- coding: binary -*-
# frozen_string_literal: true

module Msf
  module Ui
    module Console
      ###
      #
      # Module-specific datastore option validation helpers.
      #
      ###
      module ModuleOptionValidation
        def datastore_option_names(datastore)
          keys = (
            Msf::DataStore::GLOBAL_KEYS +
              datastore.options.keys
          )
          keys.concat(datastore.options.values.flat_map(&:fallbacks)) if datastore.is_a?(Msf::DataStore)
          keys.uniq!(&:downcase)
          keys
        end

        def valid_datastore_option_names(mod, include_aliases: false)
          datastore = mod ? mod.datastore : framework.datastore
          res = datastore_option_names(datastore) || []

          return res unless mod

          mod.options.each do |name, opt|
            res << name
            # aliases that are defined for backwards compatibility are not tab completed but are still valid option names
            res += opt.aliases if include_aliases
          end

          # Exploits provide these three default options
          if mod.exploit?
            res << 'PAYLOAD'
            res << 'NOP'
            res << 'TARGET'
            res << 'ENCODER'
          elsif mod.evasion?
            res << 'PAYLOAD'
            res << 'TARGET'
            res << 'ENCODER'
          elsif mod.payload?
            res << 'ENCODER'
          end

          res << 'ACTION' if mod.is_a?(Msf::Module::HasActions)

          if ((mod.exploit? || mod.evasion?) && mod.datastore['PAYLOAD'])
            payload = framework.payloads.create(mod.datastore['PAYLOAD'])
            if payload
              payload.options.each_key do |name|
                res << name
              end
            end
          end

          res
        end

        #
        # Returns an "Unknown datastore option" message (including a "Did you
        # mean" suggestion when applicable) if +name+ is not a valid option
        # name for +mod+, or nil if it is valid. Pass +valid_options+ if the
        # caller has already computed it, to avoid recomputing it here.
        #
        def unknown_datastore_option_message(mod, name, valid_options: nil)
          valid_options ||= valid_datastore_option_names(mod, include_aliases: true)
          return nil if valid_options.any? { |vo| vo.casecmp?(name) }

          message = "Unknown datastore option: #{name}."
          suggestion = DidYouMean::SpellChecker.new(dictionary: valid_options).correct(name).first
          message << " Did you mean #{suggestion}?" if suggestion
          message
        end
      end
    end
  end
end
