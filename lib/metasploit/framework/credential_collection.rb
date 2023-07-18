require 'metasploit/framework/credential'

module Metasploit::Framework

  class PrivateCredentialCollection
    # @!attribute additional_privates
    #   Additional private values that should be tried
    #   @return [Array<String>]
    attr_accessor :additional_privates

    # @!attribute blank_passwords
    #   Whether each username should be tried with a blank password
    #   @return [Boolean]
    attr_accessor :blank_passwords

    # @!attribute nil_passwords
    #   Whether each username should be tried with a nil password
    #   @return [Boolean]
    attr_accessor :nil_passwords

    # @!attribute pass_file
    #   Path to a file containing passwords, one per line
    #   @return [String]
    attr_accessor :pass_file

    # @!attribute password
    #   The password that should be tried
    #   @return [String]
    attr_accessor :password

    # @!attribute prepended_creds
    #   List of credentials to be tried before any others
    #
    #   @see #prepend_cred
    #   @return [Array<Credential>]
    attr_accessor :prepended_creds

    # @!attribute realm
    #   The authentication realm associated with this password
    #   @return [String]
    attr_accessor :realm

    # @!attribute filter
    #   A block that can be used to filter credential objects
    attr_accessor :filter

    # @option opts [Boolean] :nil_passwords See {#nil_passwords}
    # @option opts [Boolean] :blank_passwords See {#blank_passwords}
    # @option opts [String] :pass_file See {#pass_file}
    # @option opts [String] :password See {#password}
    # @option opts [Array<Credential>] :prepended_creds ([]) See {#prepended_creds}
    # @option opts [Boolean] :user_as_pass See {#user_as_pass}
    # @option opts [String] :user_file See {#user_file}
    # @option opts [String] :username See {#username}
    # @option opts [String] :userpass_file See {#userpass_file}
    # @option opts [String] :usernames_only See {#usernames_only}
    def initialize(opts = {})
      opts.each do |attribute, value|
        public_send("#{attribute}=", value)
      end
      self.prepended_creds     ||= []
      self.additional_privates ||= []
      self.filter = nil
    end

    # Adds a string as an additional private credential
    # to be combined in the collection.
    #
    # @param [String] private_str The string to use as a private credential
    # @return [void]
    def add_private(private_str='')
      additional_privates << private_str
    end

    # Add {Credential credentials} that will be yielded by {#each}
    #
    # @see prepended_creds
    # @param [Credential] cred
    # @return [self]
    def prepend_cred(cred)
      prepended_creds.unshift cred
      self
    end

    def each_filtered
      each_unfiltered do |credential|
        next unless self.filter.nil? || self.filter.call(credential)

        yield credential
      end
    end

    # Combines all the provided credential sources into a stream of {Credential}
    # objects, yielding them one at a time
    #
    # @yieldparam credential [Metasploit::Framework::Credential]
    # @return [void]
    def each_unfiltered
      if pass_file.present?
        pass_fd = File.open(pass_file, 'r:binary')
      end

      prepended_creds.each { |c| yield c }

      if password.present?
        yield Metasploit::Framework::Credential.new(private: password, realm: realm, private_type: private_type(password))
      end
      if blank_passwords
        yield Metasploit::Framework::Credential.new(private: "", realm: realm, private_type: :password)
      end
      if pass_fd
        pass_fd.each_line do |pass_from_file|
          pass_from_file.chomp!
          yield Metasploit::Framework::Credential.new(private: pass_from_file, realm: realm, private_type: private_type(pass_from_file))
        end
        pass_fd.seek(0)
      end
      additional_privates.each do |add_private|
        yield Metasploit::Framework::Credential.new(private: add_private, realm: realm, private_type: private_type(add_private))
      end

    ensure
      pass_fd.close if pass_fd && !pass_fd.closed?
    end

    # Returns true when #each will have no results to iterate
    #
    # @return [Boolean]
    def empty?
      prepended_creds.empty? && !has_privates?
    end

    # Returns true when a filter is defined
    #
    # @return [Boolean]
    def filtered?
      !self.filter.nil?
    end

    # Returns true when there are any private values set
    #
    # @return [Boolean]
    def has_privates?
      password.present? || pass_file.present? || !additional_privates.empty? || blank_passwords || nil_passwords
    end

    alias each each_filtered

    protected

    # Analyze a private value to determine its type by checking it against a known list of regular expressions
    #
    # @param [String] private The string to analyze
    # @return [Symbol]
    def private_type(private)
      if private =~ /[0-9a-f]{32}:[0-9a-f]{32}/
        :ntlm_hash
      elsif private =~ /^md5([a-f0-9]{32})$/
        :postgres_md5
      else
        :password
      end
    end
  end

  class CredentialCollection < PrivateCredentialCollection

    # @!attribute additional_publics
    #   Additional public values that should be tried
    #
    #   @return [Array<String>]
    attr_accessor :additional_publics

    # @!attribute user_as_pass
    #   Whether each username should be tried as a password for that user
    #   @return [Boolean]
    attr_accessor :user_as_pass

    # @!attribute user_file
    #   Path to a file containing usernames, one per line
    #   @return [String]
    attr_accessor :user_file

    # @!attribute username
    #   The username that should be tried
    #   @return [String]
    attr_accessor :username

    # @!attribute userpass_file
    #   Path to a file containing usernames and passwords separated by a space,
    #   one pair per line
    #   @return [String]
    attr_accessor :userpass_file

    # @!attribute anonymous_login
    #   Whether to attempt an anonymous login (blank user/pass)
    #   @return [Boolean]
    attr_accessor :anonymous_login

    # @option opts [Boolean] :blank_passwords See {#blank_passwords}
    # @option opts [String] :pass_file See {#pass_file}
    # @option opts [String] :password See {#password}
    # @option opts [Array<Credential>] :prepended_creds ([]) See {#prepended_creds}
    # @option opts [Boolean] :user_as_pass See {#user_as_pass}
    # @option opts [String] :user_file See {#user_file}
    # @option opts [String] :username See {#username}
    # @option opts [String] :userpass_file See {#userpass_file}
    def initialize(opts = {})
      super
      self.additional_publics  ||= []
    end

    # Adds a string as an additional public credential
    # to be combined in the collection.
    #
    # @param [String] public_str The string to use as a public credential
    # @return [void]
    def add_public(public_str='')
      additional_publics << public_str
    end

    # Combines all the provided credential sources into a stream of {Credential}
    # objects, yielding them one at a time
    #
    # @yieldparam credential [Metasploit::Framework::Credential]
    # @return [void]
    def each_unfiltered
      if pass_file.present?
        pass_fd = File.open(pass_file, 'r:binary')
      end

      prepended_creds.each { |c| yield c }

      if anonymous_login
        yield Metasploit::Framework::Credential.new(public: '', private: '', realm: realm, private_type: :password)
      end

      if username.present?
        if nil_passwords
          yield Metasploit::Framework::Credential.new(public: username, private: nil, realm: realm, private_type: :password)
        end
        if password.present?
          yield Metasploit::Framework::Credential.new(public: username, private: password, realm: realm, private_type: private_type(password))
        end
        if user_as_pass
          yield Metasploit::Framework::Credential.new(public: username, private: username, realm: realm, private_type: :password)
        end
        if blank_passwords
          yield Metasploit::Framework::Credential.new(public: username, private: "", realm: realm, private_type: :password)
        end
        if pass_fd
          pass_fd.each_line do |pass_from_file|
            pass_from_file.chomp!
            yield Metasploit::Framework::Credential.new(public: username, private: pass_from_file, realm: realm, private_type: private_type(pass_from_file))
          end
          pass_fd.seek(0)
        end
        additional_privates.each do |add_private|
          yield Metasploit::Framework::Credential.new(public: username, private: add_private, realm: realm, private_type: private_type(add_private))
        end
      end

      if user_file.present?
        File.open(user_file, 'r:binary') do |user_fd|
          user_fd.each_line do |user_from_file|
            user_from_file.chomp!
            if nil_passwords
              yield Metasploit::Framework::Credential.new(public: user_from_file, private: nil, realm: realm, private_type: :password)
            end
            if password.present?
              yield Metasploit::Framework::Credential.new(public: user_from_file, private: password, realm: realm, private_type: private_type(password) )
            end
            if user_as_pass
              yield Metasploit::Framework::Credential.new(public: user_from_file, private: user_from_file, realm: realm, private_type: :password)
            end
            if blank_passwords
              yield Metasploit::Framework::Credential.new(public: user_from_file, private: "", realm: realm, private_type: :password)
            end
            if pass_fd
              pass_fd.each_line do |pass_from_file|
                pass_from_file.chomp!
                yield Metasploit::Framework::Credential.new(public: user_from_file, private: pass_from_file, realm: realm, private_type: private_type(pass_from_file))
              end
              pass_fd.seek(0)
            end
            additional_privates.each do |add_private|
              yield Metasploit::Framework::Credential.new(public: user_from_file, private: add_private, realm: realm, private_type: private_type(add_private))
            end
          end
        end
      end

      if userpass_file.present?
        File.open(userpass_file, 'r:binary') do |userpass_fd|
          userpass_fd.each_line do |line|
            user, pass = line.split(" ", 2)
            if pass.blank?
              pass = ''
            else
              pass.chomp!
            end
            yield Metasploit::Framework::Credential.new(public: user, private: pass, realm: realm)
          end
        end
      end

      additional_publics.each do |add_public|
        if password.present?
          yield Metasploit::Framework::Credential.new(public: add_public, private: password, realm: realm, private_type: private_type(password) )
        end
        if user_as_pass
          yield Metasploit::Framework::Credential.new(public: add_public, private: user_from_file, realm: realm, private_type: :password)
        end
        if blank_passwords
          yield Metasploit::Framework::Credential.new(public: add_public, private: "", realm: realm, private_type: :password)
        end
        if pass_fd
          pass_fd.each_line do |pass_from_file|
            pass_from_file.chomp!
            yield Metasploit::Framework::Credential.new(public: add_public, private: pass_from_file, realm: realm, private_type: private_type(pass_from_file))
          end
          pass_fd.seek(0)
        end
        additional_privates.each do |add_private|
          yield Metasploit::Framework::Credential.new(public: add_public, private: add_private, realm: realm, private_type: private_type(add_private))
        end
      end

    ensure
      pass_fd.close if pass_fd && !pass_fd.closed?
    end

    # Returns true when #each will have no results to iterate
    #
    # @return [Boolean]
    def empty?
      prepended_creds.empty? && !has_users? && !anonymous_login || (has_users? && !has_privates?)
    end

    # Returns true when there are any user values set
    #
    # @return [Boolean]
    def has_users?
      username.present? || user_file.present? || userpass_file.present? || !additional_publics.empty?
    end

    # Returns true when there are any private values set
    #
    # @return [Boolean]
    def has_privates?
      super || userpass_file.present? || user_as_pass
    end

  end
end
