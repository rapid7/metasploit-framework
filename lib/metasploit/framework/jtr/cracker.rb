module Metasploit
  module Framework
    module JtR

      class JohnNotFoundError < StandardError
      end

      class Cracker
        include ActiveModel::Validations

        # @!attribute config
        #   @return [String] The path to an optional config file for John to use
        attr_accessor :config

        # @!attribute format
        #   @return [String] The hash format to try
        attr_accessor :format

        # @!attribute hash_path
        #   @return [String] The path to the file containing the hashes
        attr_accessor :hash_path

        # @!attribute incremental
        #   @return [String] The incremental mode to use
        attr_accessor :incremental

        # @!attribute john_path
        #   This attribute allows the user to specify a john binary to use.
        #   If not supplied, the Cracker will search the PATH for a suitable john binary
        #   and finally fall back to the pre-compiled versions shipped with Metasploit.
        #
        #   @return [String] The file path to an alternative John binary to use
        attr_accessor :john_path

        # @!attribute max_runtime
        #   @return [Integer] An optional maximum duration of the cracking attempt in seconds
        attr_accessor :max_runtime

        # @!attribute pot
        #   @return [String] The file path to an alternative John pot file to use
        attr_accessor :pot

        # @!attribute rules
        #   @return [String] The wordlist mangling rules to use inside John
        attr_accessor :rules

        # @!attribute wordlist
        #   @return [String] The file path to the wordlist to use
        attr_accessor :wordlist

        validates :config, :'Metasploit::Framework::File_path' => true, if: 'config.present?'

        validates :hash_path, :'Metasploit::Framework::File_path' => true, if: 'hash_path.present?'

        validates :john_path, :'Metasploit::Framework::Executable_path' => true, if: 'john_path.present?'

        validates :pot, :'Metasploit::Framework::File_path' => true, if: 'pot.present?'

        validates :max_runtime,
                  numericality: {
                      only_integer:             true,
                      greater_than_or_equal_to: 0
                  }, if: 'max_runtime.present?'

        validates :wordlist, :'Metasploit::Framework::File_path' => true, if: 'wordlist.present?'

        # @param attributes [Hash{Symbol => String,nil}]
        def initialize(attributes={})
          attributes.each do |attribute, value|
            public_send("#{attribute}=", value)
          end
        end

        # This method follows a decision tree to determine the path
        # to the John the Ripper binary we should use.
        #
        # @return [NilClass] if a binary path could not be found
        # @return [String] the path to the selected JtR binary
        def binary_path
          # Always prefer a manually entered path
          if john_path && ::File.file?(john_path)
            bin_path = john_path
          else
            # Look in the Environment PATH for the john binary
            path = Rex::FileUtils.find_full_path("john") ||
                Rex::FileUtils.find_full_path("john.exe")

            if path && ::File.file?(path)
              bin_path = path
            end
          end
          raise JohnNotFoundError, 'No suitable John binary was found on the system' if bin_path.blank?
          bin_path
        end

        # This method runs the command from {#crack_command} and yields each line of output.
        #
        # @yield [String] a line of output from the john command
        # @return [void]
        def crack
          ::IO.popen(crack_command, "rb") do |fd|
            fd.each_line do |line|
              yield line
            end
          end
        end

        # This method builds an array for the command to actually run the cracker.
        # It builds the command from all of the attributes on the class.
        #
        # @raise [JohnNotFoundError] if a suitable John binary was never found
        # @return [Array] An array set up for {::IO.popen} to use
        def crack_command
          cmd_string = binary_path
          cmd = [ cmd_string,  '--session=' + john_session_id, '--nolog' ]

          if config.present?
            cmd << ( "--config=" + config )
          else
            cmd << ( "--config=" + john_config_file )
          end

          if pot.present?
            cmd << ( "--pot=" + pot )
          else
            cmd << ( "--pot=" + john_pot_file)
          end

          if format.present?
            cmd << ( "--format=" + format )
          end

          if wordlist.present?
            cmd << ( "--wordlist=" + wordlist )
          end

          if incremental.present?
            cmd << ( "--incremental=" + incremental )
          end

          if rules.present?
            cmd << ( "--rules=" + rules )
          end

          if max_runtime.present?
            cmd << ( "--max-run-time=" + max_runtime.to_s)
          end

          cmd << hash_path
        end

        # This runs the show command in john and yields cracked passwords.
        #
        # @yield [String] the output lines from the command
        # @return [void]
        def each_cracked_password
          ::IO.popen(show_command, "rb") do |fd|
            fd.each_line do |line|
              yield line
            end
          end
        end

        # This method returns the path to a default john.conf file.
        #
        # @return [String] the path to the default john.conf file
        def john_config_file
          ::File.join( ::Msf::Config.data_directory, "john.conf" )
        end

        # This method returns the path to a default john.pot file.
        #
        # @return [String] the path to the default john.pot file
        def john_pot_file
          ::File.join( ::Msf::Config.config_directory, "john.pot" )
        end

        # This method is a getter for a random Session ID for John.
        # It allows us to dinstiguish between cracking sessions.
        #
        # @ return [String] the Session ID to use
        def john_session_id
          @session_id ||= ::Rex::Text.rand_text_alphanumeric(8)
        end

        # This method builds the command to show the cracked passwords.
        #
        # @raise [JohnNotFoundError] if a suitable John binary was never found
        # @return [Array] An array set up for {::IO.popen} to use
        def show_command
          cmd_string = binary_path

          pot_file = pot || john_pot_file
          cmd = [cmd_string, "--show", "--pot=#{pot_file}", "--format=#{format}" ]

          if config
            cmd << "--config=#{config}"
          else
            cmd << ( "--config=" + john_config_file )
          end

          cmd << hash_path
        end

        private




      end

    end
  end
end
