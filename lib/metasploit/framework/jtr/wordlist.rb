require 'metasploit/framework/jtr/invalid_wordlist'

module Metasploit
  module Framework
    module JtR

      class Wordlist
        include ActiveModel::Validations

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

        # @param attributes [Hash{Symbol => String,nil}]
        def initialize(attributes={})
          attributes.each do |attribute, value|
            public_send("#{attribute}=", value)
          end
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

      end

    end
  end
end