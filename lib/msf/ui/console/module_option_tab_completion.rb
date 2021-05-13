module Msf
  module Ui
    module Console
      ###
      #
      # Module-specific tab completion helper.
      #
      ###
      module ModuleOptionTabCompletion
        #
        # Tab completion for datastore names
        #
        # @param str [String] the string currently being typed before tab was hit
        # @param words [Array<String>] the previously completed words on the command
        #   line. `words` is always at least 1 when tab completion has reached this
        #   stage since the command itself has been completed.
        def tab_complete_datastore_names(mod, _str, _words)
          datastore = mod ? mod.datastore : framework.datastore
          keys = datastore.keys

          if mod
            keys = keys.delete_if do |name|
              !(mod_opt = mod.options[name]).nil? && !Msf::OptCondition.show_option(mod, mod_opt)
            end
          end
          keys
        end

        #
        # Tab completion options values
        #
        def tab_complete_option(mod, str, words)
          if str.end_with?('=')
            option_name = str.chop
            option_value = ''

            ::Readline.completion_append_character = ' '
            return tab_complete_option_values(mod, option_value, words, opt: option_name).map { |value| "#{str}#{value}" }
          elsif str.include?('=')
            str_split = str.split('=')
            option_name = str_split[0].strip
            option_value = str_split[1].strip

            ::Readline.completion_append_character = ' '
            return tab_complete_option_values(mod, option_value, words, opt: option_name).map { |value| "#{option_name}=#{value}" }
          end

          ::Readline.completion_append_character = ''
          tab_complete_option_names(mod, str, words).map { |name| "#{name}=" }
        end

        #
        # Provide tab completion for name values
        #
        def tab_complete_option_names(mod, str, words)
          res = tab_complete_datastore_names(mod, str, words) || [ ]
          # There needs to be a better way to register global options, but for
          # now all we have is an ad-hoc list of opts that the shell treats
          # specially.
          res += %w[
            ConsoleLogging
            LogLevel
            MinimumRank
            SessionLogging
            TimestampOutput
            Prompt
            PromptChar
            PromptTimeFormat
            MeterpreterPrompt
          ]
          if !mod
            return res
          end

          mod.options.sorted.each do |e|
            name, _opt = e
            next unless Msf::OptCondition.show_option(mod, _opt)

            res << name
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
          if mod.is_a?(Msf::Module::HasActions)
            res << 'ACTION'
          end
          if ((mod.exploit? || mod.evasion?) && mod.datastore['PAYLOAD'])
            p = framework.payloads.create(mod.datastore['PAYLOAD'])
            if p
              p.options.sorted.each do |e|
                name, _opt = e
                res << name
              end
            end
          end
          unless str.blank?
            res = res.select { |term| term.upcase.start_with?(str.upcase) }
            res = res.map do |term|
              if str == str.upcase
                str + term[str.length..-1].upcase
              elsif str == str.downcase
                str + term[str.length..-1].downcase
              else
                str + term[str.length..-1]
              end
            end
          end
          return res
        end

        #
        # Provide tab completion for option values
        #
        def tab_complete_option_values(mod, str, words, opt:)
          res = []
          # With no module, we have nothing to complete
          if !mod
            return res
          end

          # Well-known option names specific to exploits
          if mod.exploit?
            return option_values_payloads(mod) if opt.upcase == 'PAYLOAD'
            return option_values_targets(mod) if opt.upcase == 'TARGET'
            return option_values_nops if opt.upcase == 'NOPS'
            return option_values_encoders if opt.upcase == 'STAGEENCODER'
          elsif mod.evasion?
            return option_values_payloads(mod) if opt.upcase == 'PAYLOAD'
            return option_values_targets(mod) if opt.upcase == 'TARGET'
          end
          # Well-known option names specific to modules with actions
          if mod.is_a?(Msf::Module::HasActions)
            return option_values_actions(mod) if opt.upcase == 'ACTION'
          end
          # The ENCODER option works for evasions, payloads and exploits
          if ((mod.evasion? || mod.exploit? || mod.payload?) && (opt.upcase == 'ENCODER'))
            return option_values_encoders
          end

          # Well-known option names specific to post-exploitation
          if (mod.post? || mod.exploit?)
            return option_values_sessions(mod) if opt.upcase == 'SESSION'
          end
          # Is this option used by the active module?
          mod.options.each_key do |key|
            if key.downcase == opt.downcase
              res.concat(option_values_dispatch(mod, mod.options[key], str, words))
            end
          end
          # How about the selected payload?
          if ((mod.evasion? || mod.exploit?) && mod.datastore['PAYLOAD'])
            if p = framework.payloads.create(mod.datastore['PAYLOAD'])
              p.options.each_key do |key|
                res.concat(option_values_dispatch(mod, p.options[key], str, words)) if key.downcase == opt.downcase
              end
            end
          end
          return res
        end

        #
        # Provide possible option values based on type
        #
        def option_values_dispatch(mod, o, str, words)
          res = []
          res << o.default.to_s if o.default
          case o
          when Msf::OptAddress
            case o.name.upcase
            when 'RHOST'
              option_values_target_addrs(mod).each do |addr|
                res << addr
              end
            when 'LHOST', 'SRVHOST', 'REVERSELISTENERBINDADDRESS'
              rh = mod.datastore['RHOST'] || framework.datastore['RHOST']
              if rh && !rh.empty?
                res << Rex::Socket.source_address(rh)
              else
                res += tab_complete_source_address
                res += tab_complete_source_interface(o)
              end
            end
          when Msf::OptAddressRange
            case str
            when /^file:(.*)/
              files = tab_complete_filenames(Regexp.last_match(1), words)
              res += files.map { |f| 'file:' + f } if files
            when %r{/$}
              res << str + '32'
              res << str + '24'
              res << str + '16'
            when /\-$/
              res << str + str[0, str.length - 1]
            else
              option_values_target_addrs(mod).each do |addr|
                res << addr
              end
            end
          when Msf::OptPort
            case o.name.upcase
            when 'RPORT'
              option_values_target_ports(mod).each do |port|
                res << port
              end
            end
          when Msf::OptEnum
            o.enums.each do |val|
              res << val
            end
          when Msf::OptPath
            files = tab_complete_filenames(str, words)
            res += files if files
          when Msf::OptBool
            res << 'true'
            res << 'false'
          when Msf::OptString
            if (str =~ /^file:(.*)/)
              files = tab_complete_filenames(Regexp.last_match(1), words)
              res += files.map { |f| 'file:' + f } if files
            end
          end
          return res
        end

        # XXX: We repurpose OptAddressLocal#interfaces, so we can't put this in Rex
        def tab_complete_source_interface(o)
          return [] unless o.is_a?(Msf::OptAddressLocal)

          o.interfaces
        end

        #
        # Provide valid payload options for the current exploit
        #
        def option_values_payloads(mod)
          if @cache_payloads && mod == @previous_module && mod.target == @previous_target
            return @cache_payloads
          end

          @previous_module = mod
          @previous_target = mod.target
          @cache_payloads = mod.compatible_payloads.map do |refname, _payload|
            refname
          end
          @cache_payloads
        end

        #
        # Provide valid session options for the current post-exploit module
        #
        def option_values_sessions(mod)
          if mod.respond_to?(:compatible_sessions)
            mod.compatible_sessions.map { |sid| sid.to_s }
          end
        end

        #
        # Provide valid target options for the current exploit
        #
        def option_values_targets(mod)
          res = []
          if mod.targets
            1.upto(mod.targets.length) { |i| res << (i - 1).to_s }
            res += mod.targets.map(&:name)
          end
          return res
        end

        #
        # Provide valid action options for the current module
        #
        def option_values_actions(mod)
          res = []
          if mod.actions
            mod.actions.each { |i| res << i.name }
          end
          return res
        end

        #
        # Provide valid nops options for the current exploit
        #
        def option_values_nops
          framework.nops.map { |refname, _mod| refname }
        end

        #
        # Provide valid encoders options for the current exploit or payload
        #
        def option_values_encoders
          framework.encoders.map { |refname, _mod| refname }
        end

        #
        # Provide the target addresses
        #
        def option_values_target_addrs(mod)
          res = [ ]
          res << Rex::Socket.source_address
          return res if !framework.db.active

          # List only those hosts with matching open ports?
          mport = mod.datastore['RPORT']
          if mport
            mport = mport.to_i
            hosts = {}
            framework.db.services.each do |service|
              if service.port == mport
                hosts[service.host.address] = true
              end
            end
            hosts.keys.each do |host|
              res << host
            end
            # List all hosts in the database
          else
            framework.db.hosts.each do |host|
              res << host.address
            end
          end
          return res
        end

        #
        # Provide the target ports
        #
        def option_values_target_ports(mod)
          return [] unless framework.db.active
          return [] if mod.datastore['RHOST'].nil?

          host_addresses = mod.datastore['RHOST'].split.map do |addr|
            address, _scope = addr.split('%', 2)
            address
          end

          hosts = framework.db.hosts({:address => host_addresses, :workspace => framework.db.workspace})
          return [] if hosts.empty?

          res = []
          hosts.each do |host|
            host.services.each do |service|
              res << service.port.to_s
            end
          end

          res.uniq
        end
      end
    end
  end
end
