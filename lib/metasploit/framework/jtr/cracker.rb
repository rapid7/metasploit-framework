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
        #   @return [String] The file path to an alternative John binary to use
        attr_accessor :john_path

        # @!attribute max_runtime
        #   @return [Fixnum] An optional maximum duration of the cracking attempt in seconds
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
          if john_path && ::File.file? john_path
            bin_path = john_path
          else
            # Look in the Environment PATH for the john binary
            path = Rex::FileUtils.find_full_path("john") ||
                Rex::FileUtils.find_full_path("john.exe")

            if path && ::File.file?(path)
              bin_path = path
            else
              # If we can't find john anywhere else, look at our precompiled binaries
              bin_path = select_shipped_binary
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
          cmd = [ cmd_string,  '--session=' + john_session_id, '--nolog', '--dupe-suppression' ]

          if config.present?
            cmd << ( "--config=" + config )
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
          end

          cmd << hash_path
        end

        private

        # This method tries to identify the correct version of the pre-shipped
        # JtR binaries to use based on the platform.
        #
        # @return [NilClass] if the correct bianry could not be determined
        # @return [String] the path to the selected binary
        def select_shipped_binary
          cpuinfo_base = ::File.join(Msf::Config.data_directory, "cpuinfo")
          runpath = nil
          if File.directory?(cpuinfo_base)
            data = nil

            case ::RUBY_PLATFORM
              when /mingw|cygwin|mswin/
                fname = "#{cpuinfo_base}/cpuinfo.exe"
                if File.exists?(fname) and File.executable?(fname)
                  data = %x{"#{fname}"} rescue nil
                end
                case data
                  when /sse2/
                    run_path ||= "run.win32.sse2/john.exe"
                  when /mmx/
                    run_path ||= "run.win32.mmx/john.exe"
                  else
                    run_path ||= "run.win32.any/john.exe"
                end
              when /x86_64-linux/
                fname = "#{cpuinfo_base}/cpuinfo.ia64.bin"
                if File.exists? fname
                  ::FileUtils.chmod(0755, fname) rescue nil
                  data = %x{"#{fname}"} rescue nil
                end
                case data
                  when /mmx/
                    run_path ||= "run.linux.x64.mmx/john"
                  else
                    run_path ||= "run.linux.x86.any/john"
                end
              when /i[\d]86-linux/
                fname = "#{cpuinfo_base}/cpuinfo.ia32.bin"
                if File.exists? fname
                  ::FileUtils.chmod(0755, fname) rescue nil
                  data = %x{"#{fname}"} rescue nil
                end
                case data
                  when /sse2/
                    run_path ||= "run.linux.x86.sse2/john"
                  when /mmx/
                    run_path ||= "run.linux.x86.mmx/john"
                  else
                    run_path ||= "run.linux.x86.any/john"
                end
            end
          end
          runpath
        end



      end

    end
  end
end
