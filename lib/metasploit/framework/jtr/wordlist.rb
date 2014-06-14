
module Metasploit
  module Framework
    module JtR

      class Wordlist
        include ActiveModel::Validations

        attr_accessor :appenders
        attr_accessor :custom_wordlist
        attr_accessor :mutate
        attr_accessor :prependers
        attr_accessor :use_common_root
        attr_accessor :use_creds
        attr_accessor :use_db_info
        attr_accessor :use_default_wordlist
        attr_accessor :use_hostnames

      end

    end
  end
end