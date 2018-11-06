module Net
  module SSH

    # The Net::SSH::Config class is used to parse OpenSSH configuration files,
    # and translates that syntax into the configuration syntax that Net::SSH
    # understands. This lets Net::SSH scripts read their configuration (to
    # some extent) from OpenSSH configuration files (~/.ssh/config, /etc/ssh_config,
    # and so forth).
    #
    # Only a subset of OpenSSH configuration options are understood:
    #
    # * ChallengeResponseAuthentication => maps to the :auth_methods option challenge-response (then coleasced into keyboard-interactive)
    # * KbdInteractiveAuthentication => maps to the :auth_methods keyboard-interactive
    # * Ciphers => maps to the :encryption option
    # * Compression => :compression
    # * CompressionLevel => :compression_level
    # * ConnectTimeout => maps to the :timeout option
    # * ForwardAgent => :forward_agent
    # * GlobalKnownHostsFile => :global_known_hosts_file
    # * HostBasedAuthentication => maps to the :auth_methods option
    # * HostKeyAlgorithms => maps to :host_key option
    # * HostKeyAlias => :host_key_alias
    # * HostName => :host_name
    # * IdentityFile => maps to the :keys option
    # * IdentitiesOnly => :keys_only
    # * Macs => maps to the :hmac option
    # * PasswordAuthentication => maps to the :auth_methods option password
    # * Port => :port
    # * PreferredAuthentications => maps to the :auth_methods option
    # * ProxyCommand => maps to the :proxy option
    # * ProxyJump => maps to the :proxy option
    # * PubKeyAuthentication => maps to the :auth_methods option
    # * RekeyLimit => :rekey_limit
    # * User => :user
    # * UserKnownHostsFile => :user_known_hosts_file
    # * NumberOfPasswordPrompts => :number_of_password_prompts
    # * FingerprintHash => :fingerprint_hash
    #
    # Note that you will never need to use this class directly--you can control
    # whether the OpenSSH configuration files are read by passing the :config
    # option to Net::SSH.start. (They are, by default.)
    class Config
      class << self
        @@default_files = %w[~/.ssh/config /etc/ssh_config /etc/ssh/ssh_config]
        # The following defaults follow the openssh client ssh_config defaults.
        # http://lwn.net/Articles/544640/
        # "hostbased" is off and "none" is not supported but we allow it since
        # it's used by some clients to query the server for allowed auth methods
        @@default_auth_methods = %w[none publickey password keyboard-interactive]

        # Returns an array of locations of OpenSSH configuration files
        # to parse by default.
        def default_files
          @@default_files.clone
        end

        def default_auth_methods
          @@default_auth_methods.clone
        end

        # Loads the configuration data for the given +host+ from all of the
        # given +files+ (defaulting to the list of files returned by
        # #default_files), translates the resulting hash into the options
        # recognized by Net::SSH, and returns them.
        def for(host, files=expandable_default_files)
          translate(files.inject({}) { |settings, file|
            load(file, host, settings)
          })
        end

        # Load the OpenSSH configuration settings in the given +file+ for the
        # given +host+. If +settings+ is given, the options are merged into
        # that hash, with existing values taking precedence over newly parsed
        # ones. Returns a hash containing the OpenSSH options. (See
        # #translate for how to convert the OpenSSH options into Net::SSH
        # options.)
        def load(path, host, settings={}, base_dir = nil)
          file = File.expand_path(path)
          base_dir ||= File.dirname(file)
          return settings unless File.readable?(file)

          globals = {}
          block_matched = false
          block_seen = false
          IO.foreach(file) do |line|
            next if line =~ /^\s*(?:#.*)?$/

            if line =~ /^\s*(\S+)\s*=(.*)$/
              key, value = $1, $2
            else
              key, value = line.strip.split(/\s+/, 2)
            end

            # silently ignore malformed entries
            next if value.nil?

            key.downcase!
            value = $1 if value =~ /^"(.*)"$/

            value = case value.strip
                    when /^\d+$/ then value.to_i
                    when /^no$/i then false
                    when /^yes$/i then true
                    else value
                    end

            if key == 'host'
              # Support "Host host1 host2 hostN".
              # See http://github.com/net-ssh/net-ssh/issues#issue/6
              negative_hosts, positive_hosts = value.to_s.split(/\s+/).partition { |h| h.start_with?('!') }

              # Check for negative patterns first. If the host matches, that overrules any other positive match.
              # The host substring code is used to strip out the starting "!" so the regexp will be correct.
              negative_matched = negative_hosts.any? { |h| host =~ pattern2regex(h[1..-1]) }

              if negative_matched
                block_matched = false
              else
                block_matched = positive_hosts.any? { |h| host =~ pattern2regex(h) }
              end

              block_seen = true
              settings[key] = host
            elsif key == 'match'
              block_matched = eval_match_conditions(value, host, settings)
              block_seen = true
            elsif !block_seen
              case key
              when 'identityfile'
                (globals[key] ||= []) << value
              when 'include'
                included_file_paths(base_dir, value).each do |file_path|
                  globals = load(file_path, host, globals, base_dir)
                end
              else
                globals[key] = value unless settings.key?(key)
              end
            elsif block_matched
              case key
              when 'identityfile'
                (settings[key] ||= []) << value
              when 'include'
                included_file_paths(base_dir, value).each do |file_path|
                  settings = load(file_path, host, settings, base_dir)
                end
              else
                settings[key] = value unless settings.key?(key)
              end
            end
          end

          globals.merge(settings) do |key, oldval, newval|
            case key
            when 'identityfile'
              oldval + newval
            else
              newval
            end
          end
        end

        # Given a hash of OpenSSH configuration options, converts them into
        # a hash of Net::SSH options. Unrecognized options are ignored. The
        # +settings+ hash must have Strings for keys, all downcased, and
        # the returned hash will have Symbols for keys.
        def translate(settings)
          auth_methods = default_auth_methods.clone
          (auth_methods << 'challenge-response').uniq!
          ret = settings.each_with_object({ auth_methods: auth_methods }) do |(key, value), hash|
            translate_config_key(hash, key.to_sym, value, settings)
          end
          merge_challenge_response_with_keyboard_interactive(ret)
        end

        # Filters default_files down to the files that are expandable.
        def expandable_default_files
          default_files.keep_if do |path|
            begin
              File.expand_path(path)
              true
            rescue ArgumentError
              false
            end
          end
        end

        private

        def translate_config_key(hash, key, value, settings)
          rename = {
            bindaddress: :bind_address,
            compression: :compression,
            compressionlevel: :compression_level,
            connecttimeout: :timeout,
            forwardagent: :forward_agent,
            identitiesonly: :keys_only,
            globalknownhostsfile: :global_known_hosts_file,
            hostkeyalias: :host_key_alias,
            identityfile: :keys,
            fingerprinthash: :fingerprint_hash,
            port: :port,
            user: :user,
            userknownhostsfile: :user_known_hosts_file
          }
          case key
          when :ciphers
            hash[:encryption] = value.split(/,/)
          when :hostbasedauthentication
            if value
              (hash[:auth_methods] << "hostbased").uniq!
            else
              hash[:auth_methods].delete("hostbased")
            end
          when :hostkeyalgorithms
            hash[:host_key] = value.split(/,/)
          when :hostname
            hash[:host_name] = value.gsub(/%h/, settings['host'])
          when :macs
            hash[:hmac] = value.split(/,/)
          when :serveralivecountmax
            hash[:keepalive_maxcount] = value.to_i if value
          when :serveraliveinterval
            if value && value.to_i > 0
              hash[:keepalive] = true
              hash[:keepalive_interval] = value.to_i
            else
              hash[:keepalive] = false
            end
          when :passwordauthentication
            if value
              (hash[:auth_methods] << 'password').uniq!
            else
              hash[:auth_methods].delete('password')
            end
          when :challengeresponseauthentication
            if value
              (hash[:auth_methods] << 'challenge-response').uniq!
            else
              hash[:auth_methods].delete('challenge-response')
            end
          when :kbdinteractiveauthentication
            if value
              (hash[:auth_methods] << 'keyboard-interactive').uniq!
            else
              hash[:auth_methods].delete('keyboard-interactive')
            end
          when :preferredauthentications
            hash[:auth_methods] = value.split(/,/) # TODO we should place to preferred_auth_methods rather than auth_methods
          when :proxycommand
            if value and value !~ /^none$/
              require 'net/ssh/proxy/command'
              hash[:proxy] = Net::SSH::Proxy::Command.new(value)
            end
          when :proxyjump
            if value
              require 'net/ssh/proxy/jump'
              hash[:proxy] = Net::SSH::Proxy::Jump.new(value)
            end
          when :pubkeyauthentication
            if value
              (hash[:auth_methods] << 'publickey').uniq!
            else
              hash[:auth_methods].delete('publickey')
            end
          when :rekeylimit
            hash[:rekey_limit] = interpret_size(value)
          when :sendenv
            multi_send_env = value.to_s.split(/\s+/)
            hash[:send_env] = multi_send_env.map { |e| Regexp.new pattern2regex(e).source, false }
          when :numberofpasswordprompts
            hash[:number_of_password_prompts] = value.to_i
          when *rename.keys
            hash[rename[key]] = value
          end
        end

        # Converts an ssh_config pattern into a regex for matching against
        # host names.
        def pattern2regex(pattern)
          tail = pattern
          prefix = ""
          while !tail.empty? do
            head,sep,tail = tail.partition(/[\*\?]/)
            prefix = prefix + Regexp.quote(head)
            case sep
            when '*'
              prefix += '.*'
            when '?'
              prefix += '.'
            when ''
            else
              fail "Unpexpcted sep:#{sep}"
            end
          end
          Regexp.new("^" + prefix + "$", true)
        end

        # Converts the given size into an integer number of bytes.
        def interpret_size(size)
          case size
          when /k$/i then size.to_i * 1024
          when /m$/i then size.to_i * 1024 * 1024
          when /g$/i then size.to_i * 1024 * 1024 * 1024
          else size.to_i
          end
        end

        def merge_challenge_response_with_keyboard_interactive(hash)
          if hash[:auth_methods].include?('challenge-response')
            hash[:auth_methods].delete('challenge-response')
            (hash[:auth_methods] << 'keyboard-interactive').uniq!
          end
          hash
        end

        def included_file_paths(base_dir, config_paths)
          tokenize_config_value(config_paths).flat_map do |path|
            Dir.glob(File.expand_path(path, base_dir)).select { |f| File.file?(f) }
          end
        end

        # Tokenize string into tokens.
        # A token is a word or a quoted sequence of words, separated by whitespaces.
        def tokenize_config_value(str)
          str.scan(/([^"\s]+)?(?:"([^"]+)")?\s*/).map(&:join)
        end

        def eval_match_conditions(condition, host, settings)
          conditions = condition.split(/\s+/)
          return true if conditions == ["all"]

          conditions = conditions.each_slice(2)
          matching = true
          conditions.each do |(kind,exprs)|
            case kind.downcase
            when "all"
              raise "all cannot be mixed with other conditions"
            when "host"
              if exprs.start_with?('!')
                negated = true
                exprs = exprs[1..-1]
              else
                negated = false
              end
              condition_met = false
              exprs.split(",").each do |expr|
                condition_met = condition_met || host =~ pattern2regex(expr)
              end
              matching = matching && negated ^ condition_met
              # else
              # warn "net-ssh: Unsupported expr in Match block: #{kind}"
            end
          end
          matching
        end
      end
    end

  end
end
