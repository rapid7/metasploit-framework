require 'metasploit/framework/jtr/invalid_wordlist'

module Metasploit
  module Framework
    module JtR

      class Wordlist
        include ActiveModel::Validations

        # A mapping of the mutation substitution rules
        MUTATIONS = {
            '@' => 'a',
            '0' => 'o',
            '3' => 'e',
            '$' => 's',
            '7' => 't',
            '1' => 'l',
            '5' => 's'
        }

        # @!attribute appenders
        #   @return [Array] an array of strings to append to each word
        attr_accessor :appenders

        # @!attribute custom_wordlist
        #   @return [String] the path to a custom wordlist file to include
        attr_accessor :custom_wordlist

        # @!attribute mutate
        #   @return [TrueClass] if you want each word mutated as it is added
        #   @return [FalseClass] if you do not want each word mutated
        attr_accessor :mutate

        # @!attribute prependers
        #   @return [Array] an array of strings to prepend to each word
        attr_accessor :prependers

        # @!attribute use_common_root
        #   @return [TrueClass] if you want to use the common root words wordlist
        #   @return [FalseClass] if you do not want to use the common root words wordlist
        attr_accessor :use_common_root

        # @!attribute use_creds
        #   @return [TrueClass] if you want to seed the wordlist with existing credential data from the database
        #   @return [FalseClass] if you do not want to seed the wordlist with existing credential data from the database
        attr_accessor :use_creds

        # @!attribute use_db_info
        #   @return [TrueClass] if you want to seed the wordlist with looted database names and schemas
        #   @return [FalseClass] if you do not want to seed the wordlist with looted database names and schemas
        attr_accessor :use_db_info

        # @!attribute use_default_wordlist
        #   @return [TrueClass] if you want to use the default wordlist
        #   @return [FalseClass] if you do not want to use the default wordlist
        attr_accessor :use_default_wordlist

        # @!attribute use_hostnames
        #   @return [TrueClass] if you want to seed the wordlist with existing hostnames from the database
        #   @return [FalseClass] if you do not want to seed the wordlist with existing hostnames from the database
        attr_accessor :use_hostnames

        # @!attribute workspace
        #   @return [Mdm::Workspace] the workspace this cracker is for.
        attr_accessor :workspace

        validates :custom_wordlist, :'Metasploit::Framework::File_path' => true, if: 'custom_wordlist.present?'

        validates :mutate,
                  inclusion: { in: [true, false], message: "must be true or false"  }


        validates :use_common_root,
                  inclusion: { in: [true, false], message: "must be true or false"  }

        validates :use_creds,
                  inclusion: { in: [true, false], message: "must be true or false"  }

        validates :use_db_info,
                  inclusion: { in: [true, false], message: "must be true or false"  }

        validates :use_default_wordlist,
                  inclusion: { in: [true, false], message: "must be true or false"  }

        validates :use_hostnames,
                  inclusion: { in: [true, false], message: "must be true or false"  }

        validates :workspace,
                  presence: true

        # @param attributes [Hash{Symbol => String,nil}]
        def initialize(attributes={})
          attributes.each do |attribute, value|
            public_send("#{attribute}=", value)
          end
          @appenders  ||= []
          @prependers ||= []
        end

        # This method takes a word, and appends each word from the appenders list
        # and yields the new words.
        #
        # @yieldparam word [String] the expanded word
        # @return [void]
        def each_appended_word(word='')
          yield word
          appenders.each do |suffix|
            yield "#{word}#{suffix}"
          end
        end

        # This method checks all the attributes set on the object and calls
        # the appropriate enumerators for each option and yields the results back
        # up the call-chain.
        #
        # @yieldparam word [String] the expanded word
        # @return [void]
        def each_base_word
          # Make sure are attributes are all valid first!
          valid!

          # Yield the expanded form of each line of the custom wordlist if one was given
          if custom_wordlist.present?
            each_custom_word do |word|
              yield word unless word.blank?
            end
          end

          # Yield each word from the common root words list if it was selected
          if use_common_root
            each_root_word do |word|
              yield word unless word.blank?
            end
          end

          # If the user has selected use_creds we yield each password, username, and realm name
          # that currently exists in the database.
          if use_creds
            each_cred_word do |word|
              yield word unless word.blank?
            end
          end

          if use_db_info
            each_database_word do |word|
              yield word unless word.blank?
            end
          end

          if use_default_wordlist
            each_default_word do |word|
              yield word unless word.blank?
            end
          end

          if use_hostnames
            each_hostname_word do |word|
              yield word unless word.blank?
            end
          end

        end

        # This method searches all saved Credentials in the database
        # and yields all passwords, usernames, and realm names it finds.
        #
        # @yieldparam word [String] the expanded word
        # @return [void]
        def each_cred_word
          # We don't want all Private types here. Only Passwords make sense for inclusion in the wordlist.
          Metasploit::Credential::Password.all.each do |password|
            yield password.data
          end

          Metasploit::Credential::Public.all.each do |public|
            yield public.username
          end

          Metasploit::Credential::Realm.all.each do |realm|
            yield realm.value
          end
        end

        # This method reads the file provided as custom_wordlist and yields
        # the expanded form of each word in the list.
        #
        # @yieldparam word [String] the expanded word
        # @return [void]
        def each_custom_word
          ::File.open(custom_wordlist, "rb") do |fd|
            fd.each_line do |line|
              expanded_words(line) do |word|
                yield word
              end
            end
          end
        end

        # This method searches the notes in the current workspace
        # for DB instance names, database names, table names, and
        # column names gathered from live database servers. It yields
        # each one that it finds.
        #
        # @yieldparam word [String] the expanded word
        # @return [void]
        def each_database_word
          # Yield database, table and column names from any looted database schemas
          workspace.notes.where('ntype like ?', '%.schema%').each do |note|
            expanded_words(note.data['DBName']) do |word|
              yield word
            end

            note.data['Tables'].each do |table|
              expanded_words(table['TableName']) do |word|
                yield word
              end

              table['Columns'].each do |column|
                expanded_words(column['ColumnName']) do |word|
                  yield word
                end
              end
            end
          end

          # Yield any capture MSSQL Instance names
          workspace.notes.where(['ntype=?', 'mssql.instancename']).each do |note|
            expanded_words(note.data['InstanceName']) do |word|
              yield word
            end
          end
        end

        # This method yields expanded words taken from the default john
        # wordlist that we ship in the data directory.
        #
        # @yieldparam word [String] the expanded word
        # @return [void]
        def each_default_word
          ::File.open(default_wordlist_path, "rb") do |fd|
            fd.each_line do |line|
              expanded_words(line) do |word|
                yield word
              end
            end
          end
        end

        # This method yields the expanded words out of all the hostnames
        # found in the current workspace.
        #
        # @yieldparam word [String] the expanded word
        # @return [void]
        def each_hostname_word
          workspace.hosts.all.each do |host|
            unless host.name.nil?
              expanded_words(host.name) do |word|
                yield nil
              end
            end
          end
        end

        # This method checks to see if the user asked for mutations. If mutations
        # have been enabled, then it creates all the unique mutations and yields
        # each result.
        #
        # @yieldparam word [String] the expanded word
        # @return [void]
        def each_mutated_word(word='')
          mutants = [ ]

          # Run the mutations only if the option is set
          if mutate
            mutants = mutants + mutate_word(word)
          end

          mutants << word
          mutants.uniq.each do |mutant|
            yield mutant
          end
        end

        # This method takes a word, and prepends each word from the prependers list
        # and yields the new words.
        #
        # @yieldparam word [String] the expanded word
        # @return [void]
        def each_prepended_word(word='')
          yield word
          prependers.each do |prefix|
            yield "#{prefix}#{word}"
          end
        end

        # This method reads the common_roots.txt wordlist
        # expands any words in the list and yields them.
        #
        # @yieldparam word [String] the expanded word
        # @return [void]
        def each_root_word
          ::File.open(common_root_words_path, "rb") do |fd|
            fd.each_line do |line|
              expanded_words(line) do |word|
                yield word
              end
            end
          end
        end

        # This method wraps around all the other enumerators. It processes
        # all of the options and yields each word generated by the options
        # selected.
        #
        # @yieldparam word [String] the word to write out to the wordlist file
        # @return [void]
        def each_word
          each_base_word do |base_word|
            each_mutated_word(base_word) do |mutant|
              each_prepended_word(mutant) do |prepended|
                yield prepended
              end

              each_appended_word(mutant) do |appended|
                yield appended
              end
            end
          end
        end

        # This method takes a string and splits it on non-word characters
        # and the underscore. It does this to find likely distinct words
        # in the string. It then yields each 'word' found this way.
        #
        # @param word [String] the string to split apart
        # @yieldparam expanded [String] the expanded words
        # @return [void]
        def expanded_words(word='')
          word.split(/[\W_]+/).each do |expanded|
            yield expanded
          end
        end

        # This method takes a word and applies various mutation rules to that word
        # and returns an array of all the mutated forms.
        #
        # @param word [String] the word to apply the mutations to
        # @return [Array<String>] An array containing all the mutated forms of the word
        def mutate_word(word)
          results = []
          # Iterate through combinations to create each possible mutation
          mutation_keys.each do |iteration|
            next if iteration.flatten.empty?
            intermediate = word.dup
            subsititutions = iteration.collect { |key| MUTATIONS[key] }
            intermediate.tr!(subsititutions.join, iteration.join)
            results << intermediate
          end
          results.flatten.uniq
        end

        # A getter for a memoized version fo the mutation keys list
        #
        # @return [Array<Array>] a 2D array of all mutation combinations
        def mutation_keys
          @mutation_keys ||= generate_mutation_keys
        end

        # This method takes all the options provided and streams the generated wordlist out
        # to a {Rex::Quickfile} and returns the {Rex::Quickfile}.
        #
        # @param max_len [Integer] max length of a word in the wordlist, 0 default for ignored value
        # @return [Rex::Quickfile] The {Rex::Quickfile} object that the wordlist has been written to
        def to_file(max_len = 0)
          valid!
          wordlist_file = Rex::Quickfile.new("jtrtmp")
          each_word do |word|
            wordlist_file.puts max_len == 0 ? word : word[0...max_len]
          end
          wordlist_file
        end

        # Raise an exception if the attributes are not valid.
        #
        # @raise [Invalid] if the attributes are not valid on this scanner
        # @return [void]
        def valid!
          unless valid?
            raise Metasploit::Framework::JtR::InvalidWordlist.new(self)
          end
          nil
        end



        private

        # This method returns the path to the common_roots.txt wordlist
        #
        # @return [String] the file path to the common_roots.txt file
        def common_root_words_path
          ::File.join(Msf::Config.data_directory, 'wordlists', 'common_roots.txt')
        end

        # This method returns the path to the passwords.lst wordlist
        #
        # @return [String] the file path to the passwords.lst file
        def default_wordlist_path
          ::File.join(Msf::Config.data_directory, 'wordlists', 'password.lst')
        end

        def generate_mutation_keys
          iterations = MUTATIONS.keys.dup

          # Find PowerSet of all possible mutation combinations
          iterations.inject([[]]) do |accumulator,mutation_key|
            power_set = []
            accumulator.each do |i|
              power_set << i
              power_set << i+[mutation_key]
            end
            power_set
          end
        end

      end

    end
  end
end
