require 'metasploit/framework/credential'

module Metasploit
  module Framework

    # This class is responsible for taking datastore options from the snmp_login module
    # and yielding appropriate {Metasploit::Framework::Credential}s to the {Metasploit::Framework::LoginScanner::SNMP}.
    # This one has to be different from credentialCollection as it will only have a {Metasploit::Framework::Credential#public}
    # It may be slightly confusing that the attribues are called password and pass_file, because this is what the legacy
    # module used. However, community Strings are now considered more to be public credentials than private ones.
    class CommunityStringCollection
      # @!attribute pass_file
      #   Path to a file containing passwords, one per line
      #   @return [String]
      attr_accessor :pass_file

      # @!attribute password
      #   @return [String]
      attr_accessor :password

      # @!attribute prepended_creds
      #   List of credentials to be tried before any others
      #
      #   @see #prepend_cred
      #   @return [Array<Credential>]
      attr_accessor :prepended_creds

      # @option opts [String] :pass_file See {#pass_file}
      # @option opts [String] :password See {#password}
      # @option opts [Array<Credential>] :prepended_creds ([]) See {#prepended_creds}
      def initialize(opts = {})
        opts.each do |attribute, value|
          public_send("#{attribute}=", value)
        end
        self.prepended_creds ||= []
      end

      # Combines all the provided credential sources into a stream of {Credential}
      # objects, yielding them one at a time
      #
      # @yieldparam credential [Metasploit::Framework::Credential]
      # @return [void]
      def each
        begin
          if pass_file.present?
            pass_fd = File.open(pass_file, 'r:binary')
            pass_fd.each_line do |line|
              line.chomp!
              yield Metasploit::Framework::Credential.new(public: line, paired: false)
            end
          end

          if password.present?
            yield Metasploit::Framework::Credential.new(public: password, paired: false)
          end

        ensure
          pass_fd.close if pass_fd && !pass_fd.closed?
        end
      end

      def empty?
        prepended_creds.empty? && !pass_file.present? && !password.present?
      end

      # Add {Credential credentials} that will be yielded by {#each}
      #
      # @see prepended_creds
      # @param cred [Credential]
      # @return [self]
      def prepend_cred(cred)
        prepended_creds.unshift cred
        self
      end

    end
  end
end
