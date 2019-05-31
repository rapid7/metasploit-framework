module Metasploit
  module Framework
    module PasswordCracker

      class PasswordCrackerNotFoundError < StandardError
      end

      class Cracker
        include ActiveModel::Validations

        # @!attribute attack
        #   @return [String] The attack mode for hashcat to use (not applicable to John)
        attr_accessor :attack

        # @!attribute config
        #   @return [String] The path to an optional config file for John to use
        attr_accessor :config

        # @!attribute cracker
        #   @return [String] Which cracker to use.  'john' and 'hashcat' are valid
        attr_accessor :cracker

        # @!attribute cracker_path
        #   This attribute allows the user to specify a cracker binary to use.
        #   If not supplied, the Cracker will search the PATH for a suitable john or hashcat binary
        #   and finally fall back to the pre-compiled john versions shipped with Metasploit.
        #
        #   @return [String] The file path to an alternative cracker binary to use
        attr_accessor :cracker_path

        # @!attribute format
        #   If the cracker type is john, this format will automatically be translated
        #   to the hashcat equivalent via jtr_format_to_hashcat_format
        #
        #   @return [String] The hash format to try.
        attr_accessor :format

        # @!attribute fork
        #   If the cracker type is john, the amount of forks to specify
        #
        #   @return [String] The hash format to try.
        attr_accessor :fork

        # @!attribute hash_path
        #   @return [String] The path to the file containing the hashes
        attr_accessor :hash_path

        # @!attribute incremental
        #   @return [String] The incremental mode to use
        attr_accessor :incremental

        # @!attribute max_runtime
        #   @return [Integer] An optional maximum duration of the cracking attempt in seconds
        attr_accessor :max_runtime

        # @!attribute max_length
        #   @return [Integer] An optional maximum length of password to attempt cracking
        attr_accessor :max_length

        # @!attribute pot
        #   @return [String] The file path to an alternative John pot file to use
        attr_accessor :pot

        # @!attribute rules
        #   @return [String] The wordlist mangling rules to use inside John/Hashcat
        attr_accessor :rules

        # @!attribute wordlist
        #   @return [String] The file path to the wordlist to use
        attr_accessor :wordlist

        validates :config, :'Metasploit::Framework::File_path' => true, if: 'config.present?'

        validates :cracker, inclusion: {in: %w(john hashcat)} 

        validates :cracker_path, :'Metasploit::Framework::Executable_path' => true, if: 'cracker_path.present?'

        validates :fork,
                  numericality: {
                      only_integer:             true,
                      greater_than_or_equal_to: 1
                  }, if: 'fork.present?'

        validates :hash_path, :'Metasploit::Framework::File_path' => true, if: 'hash_path.present?'

        validates :pot, :'Metasploit::Framework::File_path' => true, if: 'pot.present?'

        validates :max_runtime,
                  numericality: {
                      only_integer:             true,
                      greater_than_or_equal_to: 0
                  }, if: 'max_runtime.present?'

        validates :max_length,
                  numericality: {
                      only_integer:             true,
                      greater_than_or_equal_to: 0
                  }, if: 'max_length.present?'

        validates :wordlist, :'Metasploit::Framework::File_path' => true, if: 'wordlist.present?'

        # @param attributes [Hash{Symbol => String,nil}]
        def initialize(attributes={})
          attributes.each do |attribute, value|
            public_send("#{attribute}=", value)
          end
        end

        # This method takes a {framework.db.cred.private.jtr_format} (string), and
        # returns the string number associated to the hashcat format
        #
        # @param[String] a jtr_format string
        # @return [String] the format number for Hashcat
        def jtr_format_to_hashcat_format(format)
          case format
          when 'md5crypt'
            return '500'
          when 'descrypt'
            return '1500'
          when 'bsdicrypt'
            return '12400'
          when 'sha256crypt'
            return '7400'
          when 'sha512crypt'
            return '1800'
          when 'bcrypt'
            return '3200'
          when 'lm', 'lanman'
            return '3000'
          when 'nt', 'ntlm'
            return '1000'
          when 'mssql'
            return '131'
          when 'mssql05'
            return '132'
          when 'mssql12'
            return '1731'
          # hashcat requires a format we dont have all the data for
          # in the current dumper, so this is disabled in module and lib
          #when 'oracle', 'des,oracle'
          #  return '3100'
          when 'oracle11', 'raw-sha1,oracle'
            return '112'
          when 'oracle12c', 'pbkdf2,oracle12c'
            return '12300'
          when 'postgres', 'dynamic_1034', 'raw-md5,postgres'
            return '12'
          when 'mysql'
            return '200'
          when 'mysql-sha1'
            return '300'
          when 'PBKDF2-HMAC-SHA512' #osx 10.8+
            return '7100'
          when 'xsha' #osx 10.4-6
            return '122'
          when 'xsha512' #osx 10.7
            return '1722'
          when 'PBKDF2-HMAC-SHA1' #Atlassian
            return '12001'
          when 'phpass' #Wordpress/PHPass, Joomla, phpBB3
            return '400'
          when 'mediawiki' # mediawiki b type
            return '3711'
          end
          nil
        end


        # This method sets the appropriate parameters to run a cracker in incremental mode
        def mode_incremental
          if cracker == 'john'
            self.wordlist = nil
            self.rules = nil
            self.incremental = 'Digits'
          elsif cracker == 'hashcat'
            self.wordlist = nil
            self.attack = '3'
            self.incremental = true
          end
        end


        # This method sets the appropriate parameters to run a cracker in wordlist mode
        #
        # @param[String] a file location of the wordlist to use
        def mode_wordlist(file)
          if cracker == 'john'
            self.wordlist = file
            self.rules = 'wordlist'
            self.incremental = nil
          elsif cracker == 'hashcat'
            self.wordlist = file
            self.attack = '0'
            self.incremental = nil
          end
        end


        # This method sets the john to 'normal' mode
        def mode_normal
          if cracker == 'john'
            self.wordlist = nil
            self.rules = nil
            self.incremental = nil
          end
        end


        # This method sets the john to single mode
        #
        # @param[String] a file location of the wordlist to use
        def mode_single(file)
          if cracker == 'john'
            self.wordlist = file
            self.rules = 'single'
            self.incremental = nil
          end
        end


        # This method follows a decision tree to determine the path
        # to the cracker binary we should use.
        #
        # @return [NilClass] if a binary path could not be found
        # @return [String] the path to the selected JtR binary
        def binary_path
          # Always prefer a manually entered path
          if cracker_path && ::File.file?(cracker_path)
            bin_path = cracker_path
          else
            # Look in the Environment PATH for the john binary
            if cracker == 'john'
              path = Rex::FileUtils.find_full_path("john") ||
                Rex::FileUtils.find_full_path("john.exe")
            elsif cracker == 'hashcat'
              path = Rex::FileUtils.find_full_path("hashcat") ||
                Rex::FileUtils.find_full_path("hashcat.exe")
            else
              raise PasswordCrackerNotFoundError, 'No suitable Cracker was selected, so a binary could not be found on the system'
            end

            if path && ::File.file?(path)
              bin_path = path
            end
          end
          raise PasswordCrackerNotFoundError, 'No suitable john/hashcat binary was found on the system' if bin_path.blank?
          bin_path
        end

        # This method runs the command from {#crack_command} and yields each line of output.
        #
        # @yield [String] a line of output from the cracker command
        # @return [void]
        def crack
          if cracker == 'john'
            results = john_crack_command
          elsif cracker == 'hashcat'
            results = hashcat_crack_command
          end
          ::IO.popen(results, "rb") do |fd|
            fd.each_line do |line|
              yield line
            end
          end
        end

        # This method returns the version of John the Ripper or Hashcat being used.
        #
        # @raise [PasswordCrackerNotFoundError] if a suitable cracker binary was never found
        # @return [Sring] the version detected
        def cracker_version
          if cracker == 'john'
            cmd = binary_path
          elsif cracker == 'hashcat'
            cmd = binary_path
            cmd << (" -V")
          end
          ::IO.popen(cmd, "rb") do |fd|
            fd.each_line do |line|
              if cracker == 'john'
                # John the Ripper 1.8.0.13-jumbo-1-bleeding-973a245b96 2018-12-17 20:12:51 +0100 OMP [linux-gnu 64-bit x86_64 AVX2 AC]
                # John the Ripper 1.9.0-jumbo-1 OMP [linux-gnu 64-bit x86_64 AVX2 AC]
                #return $1 if line =~ /John the Ripper ([\.\w-]+) 20\d{2}-\d{2}-\d{2}/
                return $1 if line =~ /John the Ripper (.+) \[/
              elsif cracker == 'hashcat'
                # v5.1.0
                return $1 if line =~ /(v[\d\.]+)/
              end
            end
          end
          nil
        end

        # This method builds an array for the command to actually run the cracker.
        # It builds the command from all of the attributes on the class.
        #
        # @raise [PasswordCrackerNotFoundError] if a suitable John binary was never found
        # @return [Array] An array set up for {::IO.popen} to use
        def john_crack_command
          cmd_string = binary_path
          cmd = [ cmd_string,  '--session=' + cracker_session_id, '--nolog' ]

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

          if fork.present? && fork > 1
            cmd << ( "--fork=" + fork.to_s )
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

          if max_length.present?
            cmd << ( "--max-len=" + max_length.to_s)
          end

          cmd << hash_path
        end

        # This method builds an array for the command to actually run the cracker.
        # It builds the command from all of the attributes on the class.
        #
        # @raise [PasswordCrackerNotFoundError] if a suitable Hashcat binary was never found
        # @return [Array] An array set up for {::IO.popen} to use
        def hashcat_crack_command
          cmd_string = binary_path
          cmd = [ cmd_string,  '--session=' + cracker_session_id, '--logfile-disable' ]

          if pot.present?
            cmd << ( "--potfile-path=" + pot )
          else
            cmd << ( "--potfile-path=" + john_pot_file)
          end

          if format.present?
            cmd << ( "--hash-type=" + jtr_format_to_hashcat_format(format) )
          end

          if incremental.present?
            cmd << ( "--increment")
            cmd << ( "--increment-max=4") 
            # anything more than max 4 on even des took 8+min on an i7.
            # maybe in the future this can be adjusted or made a variable
            # but current time, we'll leave it as this seems like reasonable
            # time expectation for a module to run
          end

          if rules.present?
            cmd << ( "--rules-file=" + rules )
          end

          if attack.present?
            cmd << ( "--attack-mode=" + attack )
          end

          if max_runtime.present?
            cmd << ( "--runtime=" + max_runtime.to_s)
          end

          cmd << hash_path

          # must be last
          if wordlist.present?
            cmd << ( wordlist )
          end
          cmd
        end

        # This runs the show command in john and yields cracked passwords.
        #
        # @return [Array] the output from teh command split on newlines
        def each_cracked_password
          ::IO.popen(show_command, "rb").readlines
        end

        # This method returns the path to a default john.conf file.
        #
        # @return [String] the path to the default john.conf file
        def john_config_file
          ::File.join( ::Msf::Config.data_directory, "jtr", "john.conf" )
        end

        # This method returns the path to a default john.pot file.
        #
        # @return [String] the path to the default john.pot file
        def john_pot_file
          ::File.join( ::Msf::Config.config_directory, "john.pot" )
        end

        # This method is a getter for a random Session ID for the cracker.
        # It allows us to dinstiguish between cracking sessions.
        #
        # @ return [String] the Session ID to use
        def cracker_session_id
          @session_id ||= ::Rex::Text.rand_text_alphanumeric(8)
        end

        # This method builds the command to show the cracked passwords.
        #
        # @raise [JohnNotFoundError] if a suitable John binary was never found
        # @return [Array] An array set up for {::IO.popen} to use
        def show_command
          cmd_string = binary_path

          pot_file = pot || john_pot_file
          if cracker=='hashcat'
            cmd = [cmd_string, "--show", "--potfile-path=#{pot_file}", "--hash-type=#{jtr_format_to_hashcat_format(format)}" ]
          elsif cracker=='john'
            cmd = [cmd_string, "--show", "--pot=#{pot_file}", "--format=#{format}" ]

            if config
              cmd << "--config=#{config}"
            else
              cmd << ( "--config=" + john_config_file )
            end
          end
          cmd << hash_path
        end

        private

      end

    end
  end
end
