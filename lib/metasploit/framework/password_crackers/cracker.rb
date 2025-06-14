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

        # @!attribute increment_length
        #   @return [Array] The incremental min and max to use
        attr_accessor :increment_length

        # @!attribute mask
        #  If the cracker type is hashcat, If set, the mask to use.  Should consist of the character sets
        #  pre-defined by hashcat, such as ?d ?s ?l etc
        #
        #   @return [String] The mask to use
        attr_accessor :mask

        # @!attribute max_runtime
        #   @return [Integer] An optional maximum duration of the cracking attempt in seconds
        attr_accessor :max_runtime

        # @!attribute max_length
        #   @return [Integer] An optional maximum length of password to attempt cracking
        attr_accessor :max_length

        # @!attribute optimize
        #   @return [Boolean] If the Optimize flag should be given to Hashcat
        attr_accessor :optimize

        # @!attribute pot
        #   @return [String] The file path to an alternative John pot file to use
        attr_accessor :pot

        # @!attribute rules
        #   @return [String] The wordlist mangling rules to use inside John/Hashcat
        attr_accessor :rules

        # @!attribute wordlist
        #   @return [String] The file path to the wordlist to use
        attr_accessor :wordlist

        validates :config, 'Metasploit::Framework::File_path': true, if: -> { config.present? }

        validates :cracker, inclusion: { in: %w[john hashcat] }

        validates :cracker_path, 'Metasploit::Framework::Executable_path': true, if: -> { cracker_path.present? }

        validates :fork,
                  numericality: {
                    only_integer: true,
                    greater_than_or_equal_to: 1
                  }, if: -> { fork.present? }

        validates :hash_path, 'Metasploit::Framework::File_path': true, if: -> { hash_path.present? }

        validates :pot, 'Metasploit::Framework::File_path': true, if: -> { pot.present? }

        validates :max_runtime,
                  numericality: {
                    only_integer: true,
                    greater_than_or_equal_to: 0
                  }, if: -> { max_runtime.present? }

        validates :max_length,
                  numericality: {
                    only_integer: true,
                    greater_than_or_equal_to: 0
                  }, if: -> { max_length.present? }

        validates :wordlist, 'Metasploit::Framework::File_path': true, if: -> { wordlist.present? }

        # @param attributes [Hash{Symbol => String,nil}]
        def initialize(attributes = {})
          attributes.each do |attribute, value|
            public_send("#{attribute}=", value)
          end
        end

        # This method takes a {framework.db.cred.private.jtr_format} (string), and
        # returns the string number associated to the hashcat format
        #
        # @param format [String] A jtr_format string
        # @return [String] The format number for Hashcat
        def jtr_format_to_hashcat_format(format)
          case format
          # nix
          when 'md5crypt'
            '500'
          when 'descrypt'
            '1500'
          when 'bsdicrypt'
            '12400'
          when 'sha256crypt'
            '7400'
          when 'sha512crypt'
            '1800'
          when 'bcrypt'
            '3200'
          # windows
          when 'lm', 'lanman'
            '3000'
          when 'nt', 'ntlm'
            '1000'
          when 'mscash'
            '1100'
          when 'mscash2'
            '2100'
          when 'netntlm'
            '5500'
          when 'netntlmv2'
            '5600'
          # dbs
          when 'mssql'
            '131'
          when 'mssql05'
            '132'
          when 'mssql12'
            '1731'
          # hashcat requires a format we dont have all the data for
          # in the current dumper, so this is disabled in module and lib
          # when 'oracle', 'des,oracle'
          #  return '3100'
          when 'oracle11', 'raw-sha1,oracle'
            '112'
          when 'oracle12c', 'pbkdf2,oracle12c'
            '12300'
          when 'postgres', 'dynamic_1034', 'raw-md5,postgres'
            '12'
          when 'mysql'
            '200'
          when 'mysql-sha1'
            '300'
          when 'PBKDF2-HMAC-SHA512' # osx 10.8+
            '7100'
          # osx
          when 'xsha' # osx 10.4-6
            '122'
          when 'xsha512' # osx 10.7
            '1722'
          # webapps
          when 'PBKDF2-HMAC-SHA1' # Atlassian
            '12001'
          when 'phpass' # Wordpress/PHPass, Joomla, phpBB3
            '400'
          when 'mediawiki' # mediawiki b type
            '3711'
          # mobile
          when 'android-samsung-sha1'
            '5800'
          when 'android-sha1'
            '110'
          when 'android-md5'
            '10'
          when 'hmac-md5'
            '10200'
          when 'dynamic_82'
            '1710'
          when 'ssha'
            '111'
          when 'raw-sha512'
            '1700'
          when 'raw-sha256'
            '1400'
          when 'raw-sha1'
            '100'
          when 'raw-md5'
            '0'
          when 'smd5'
            '6300'
          when 'ssha256'
            '1411'
          when 'ssha512'
            '1711'
          when 'Raw-MD5u'
            '30'
          when 'pbkdf2-sha256'
            '10900'
          end
        end

        # This method sets the appropriate parameters to run a cracker in incremental mode
        def mode_incremental
          self.increment_length = nil
          self.wordlist = nil
          self.mask = nil
          self.max_runtime = nil
          if cracker == 'john'
            self.rules = nil
            self.incremental = 'Digits'
          elsif cracker == 'hashcat'
            self.attack = '3'
            self.incremental = true
          end
        end

        # This method sets the appropriate parameters to run a cracker in wordlist mode
        #
        # @param file [String] A file location of the wordlist to use
        def mode_wordlist(file)
          self.increment_length = nil
          self.incremental = nil
          self.max_runtime = nil
          self.mask = nil
          if cracker == 'john'
            self.wordlist = file
            self.rules = 'wordlist'
          elsif cracker == 'hashcat'
            self.wordlist = file
            self.attack = '0'
          end
        end

        # This method sets the appropriate parameters to run a cracker in a pin mode (4-8 digits) on hashcat
        def mode_pin
          self.rules = nil
          if cracker == 'hashcat'
            self.attack = '3'
            self.mask = '?d' * 8
            self.incremental = true
            self.increment_length = [4, 8]
            self.max_runtime = 300 # 5min on an i7 got through 4-7 digits. 8digit was 32min more
          end
        end

        # This method sets the john to 'normal' mode
        def mode_normal
          if cracker == 'john'
            self.max_runtime = nil
            self.mask = nil
            self.wordlist = nil
            self.rules = nil
            self.incremental = nil
            self.increment_length = nil
          end
        end

        # This method sets the john to single mode
        #
        # @param file [String] A file location of the wordlist to use
        def mode_single(file)
          if cracker == 'john'
            self.wordlist = file
            self.rules = 'single'
            self.incremental = nil
            self.increment_length = nil
            self.mask = nil
          end
        end

        # This method follows a decision tree to determine the path
        # to the cracker binary we should use.
        #
        # @return [String, NilClass] Returns Nil if a binary path could not be found, or a String containing the path to the selected JTR binary on success.
        def binary_path
          # Always prefer a manually entered path
          if cracker_path && ::File.file?(cracker_path)
            return cracker_path
          else
            # Look in the Environment PATH for the john binary
            if cracker == 'john'
              path = Rex::FileUtils.find_full_path('john') ||
                     Rex::FileUtils.find_full_path('john.exe')
            elsif cracker == 'hashcat'
              path = Rex::FileUtils.find_full_path('hashcat') ||
                     Rex::FileUtils.find_full_path('hashcat.exe')
            else
              raise PasswordCrackerNotFoundError, 'No suitable Cracker was selected, so a binary could not be found on the system'
            end

            if path && ::File.file?(path)
              return path
            end

            raise PasswordCrackerNotFoundError, 'No suitable john/hashcat binary was found on the system'
          end
        end

        # This method runs the command from {#crack_command} and yields each line of output.
        #
        # @yield [String] a line of output from the cracker command
        # @return [void]
        def crack(&block)
          if cracker == 'john'
            results = john_crack_command
          elsif cracker == 'hashcat'
            results = hashcat_crack_command
          end
          ::IO.popen(results, 'rb') do |fd|
            fd.each_line(&block)
          end
        end

        # This method returns the version of John the Ripper or Hashcat being used.
        #
        # @raise [PasswordCrackerNotFoundError] if a suitable cracker binary was never found
        # @return [String] the version detected
        def cracker_version
          if cracker == 'john'
            cmd = binary_path
          elsif cracker == 'hashcat'
            cmd = binary_path
            cmd << (' -V')
          end
          ::IO.popen(cmd, 'rb') do |fd|
            fd.each_line do |line|
              if cracker == 'john'
                # John the Ripper 1.8.0.13-jumbo-1-bleeding-973a245b96 2018-12-17 20:12:51 +0100 OMP [linux-gnu 64-bit x86_64 AVX2 AC]
                # John the Ripper 1.9.0-jumbo-1 OMP [linux-gnu 64-bit x86_64 AVX2 AC]
                # John the Ripper password cracker, version 1.8.0.2-bleeding-jumbo_omp [64-bit AVX-autoconf]
                # John the Ripper password cracker, version 1.8.0
                return Regexp.last_match(1).strip if line =~ /John the Ripper(?: password cracker, version)? ([^\[]+)/
              elsif cracker == 'hashcat'
                # v5.1.0
                return Regexp.last_match(1) if line =~ /(v[\d.]+)/
              end
            end
          end
          nil
        end

        # This method is used to determine which format of the no log option should be used
        # --no-log vs --nolog https://github.com/openwall/john/commit/8982e4f7a2e874aab29807a05b421373015c9b61
        # We base this either on a date being in the version, or running the command and checking the output
        #
        # @return [String] The nolog format to use
        def john_nolog_format
          if /(\d{4}-\d{2}-\d{2})/ =~ cracker_version
            # we lucked out and theres a date, we'll check its older than the commit that changed the nolog
            if Date.parse(Regexp.last_match(1)) < Date.parse('2020-11-27')
              return '--nolog'
            end

            return '--no-log'
          end

          # no date, so lets give it a run with the old format and check if we raise an error
          # on *nix 'unknown option' goes to stderr
          ::IO.popen([binary_path, '--nolog', { err: %i[child out] }], 'rb') do |fd|
            return '--nolog' unless fd.read.include? 'Unknown option'
          end
          '--no-log'
        end

        # This method builds an array for the command to actually run the cracker.
        # It builds the command from all of the attributes on the class.
        #
        # @raise [PasswordCrackerNotFoundError] if a suitable John binary was never found
        # @return [Array] An array set up for {::IO.popen} to use
        def john_crack_command
          cmd_string = binary_path

          cmd = [cmd_string, '--session=' + cracker_session_id, john_nolog_format]

          if config.present?
            cmd << ('--config=' + config)
          else
            cmd << ('--config=' + john_config_file)
          end

          if pot.present?
            cmd << ('--pot=' + pot)
          else
            cmd << ('--pot=' + john_pot_file)
          end

          if fork.present? && fork > 1
            cmd << ('--fork=' + fork.to_s)
          end

          if format.present?
            cmd << ('--format=' + format)
          end

          if wordlist.present?
            cmd << ('--wordlist=' + wordlist)
          end

          if incremental.present?
            cmd << ('--incremental=' + incremental)
          end

          if rules.present?
            cmd << ('--rules=' + rules)
          end

          if max_runtime.present?
            cmd << ('--max-run-time=' + max_runtime.to_s)
          end

          if max_length.present?
            cmd << ('--max-len=' + max_length.to_s)
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
          cmd = [cmd_string, '--session=' + cracker_session_id, '--logfile-disable', '--quiet', '--username']

          if pot.present?
            cmd << ('--potfile-path=' + pot)
          else
            cmd << ('--potfile-path=' + john_pot_file)
          end

          if format.present?
            cmd << ('--hash-type=' + jtr_format_to_hashcat_format(format))
          end

          if optimize.present?
            # https://hashcat.net/wiki/doku.php?id=frequently_asked_questions#what_is_the_maximum_supported_password_length_for_optimized_kernels
            # Optimized Kernels has a large impact on speed.  Here are some stats from Hashcat 5.1.0:

            # Kali Linux on Dell Precision M3800
            ## hashcat -b -w 2 -m 0
            # * Device #1: Quadro K1100M, 500/2002 MB allocatable, 2MCU
            # Speed.#1.........:   185.9 MH/s (11.15ms) @ Accel:64 Loops:16 Thr:1024 Vec:1

            ## hashcat -b -w 2 -O -m 0
            # * Device #1: Quadro K1100M, 500/2002 MB allocatable, 2MCU
            # Speed.#1.........:   463.6 MH/s (8.92ms) @ Accel:64 Loops:32 Thr:1024 Vec:1

            # Windows 10
            # PS C:\hashcat-5.1.0> .\hashcat64.exe -b -O -w 2 -m 0
            # * Device #1: GeForce RTX 2070 SUPER, 2048/8192 MB allocatable, 40MCU
            # Speed.#1.........: 13914.0 MH/s (5.77ms) @ Accel:128 Loops:64 Thr:256 Vec:1

            # PS C:\hashcat-5.1.0> .\hashcat64.exe -b -O -w 2 -m 0
            # * Device #1: GeForce RTX 2070 SUPER, 2048/8192 MB allocatable, 40MCU
            # Speed.#1.........: 31545.6 MH/s (10.36ms) @ Accel:256 Loops:128 Thr:256 Vec:1

            # This change should result in 225%-250% speed boost at the sacrifice of some password length, which most likely
            # wouldn't be tested inside of MSF since most users are using the MSF modules for word list and easy cracks.
            # Anything of length where this would cut off is most likely being done independently (outside MSF)

            cmd << ('-O')
          end

          if incremental.present?
            cmd << ('--increment')
            if increment_length.present?
              cmd << ('--increment-min=' + increment_length[0].to_s)
              cmd << ('--increment-max=' + increment_length[1].to_s)
            else
              # anything more than max 4 on even des took 8+min on an i7.
              # maybe in the future this can be adjusted or made a variable
              # but current time, we'll leave it as this seems like reasonable
              # time expectation for a module to run
              cmd << ('--increment-max=4')
            end
          end

          if rules.present?
            cmd << ('--rules-file=' + rules)
          end

          if attack.present?
            cmd << ('--attack-mode=' + attack)
          end

          if max_runtime.present?
            cmd << ('--runtime=' + max_runtime.to_s)
          end

          cmd << hash_path

          if mask.present?
            cmd << mask.to_s
          end

          # must be last
          if wordlist.present?
            cmd << (wordlist)
          end
          cmd
        end

        # This runs the show command in john and yields cracked passwords.
        #
        # @return [Array] the output from the command split on newlines
        def each_cracked_password
          ::IO.popen(show_command, 'rb').readlines
        end

        # This method returns the path to a default john.conf file.
        #
        # @return [String] the path to the default john.conf file
        def john_config_file
          ::File.join(::Msf::Config.data_directory, 'jtr', 'john.conf')
        end

        # This method returns the path to a default john.pot file.
        #
        # @return [String] the path to the default john.pot file
        def john_pot_file
          ::File.join(::Msf::Config.config_directory, 'john.pot')
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
          if cracker == 'hashcat'
            cmd = [cmd_string, '--show', '--username', "--potfile-path=#{pot_file}", "--hash-type=#{jtr_format_to_hashcat_format(format)}"]
          elsif cracker == 'john'
            cmd = [cmd_string, '--show', "--pot=#{pot_file}", "--format=#{format}"]

            if config
              cmd << "--config=#{config}"
            else
              cmd << ('--config=' + john_config_file)
            end
          end
          cmd << hash_path
        end

      end
    end
  end
end
