require 'metasploit/framework/credential'

class Metasploit::Framework::CredentialCollection

  # @!attribute blank_passwords
  #   Whether each username should be tried with a blank password
  #   @return [Boolean]
  attr_accessor :blank_passwords

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

  # @!attribute realm
  #   @return [String]
  attr_accessor :realm

  # @!attribute user_as_pass
  #   Whether each username should be tried as a password for that user
  #   @return [Boolean]
  attr_accessor :user_as_pass

  # @!attribute user_file
  #   Path to a file containing usernames, one per line
  #   @return [String]
  attr_accessor :user_file

  # @!attribute username
  #   @return [String]
  attr_accessor :username

  # @!attribute userpass_file
  #   Path to a file containing usernames and passwords separated by a space,
  #   one pair per line
  #   @return [String]
  attr_accessor :userpass_file

  # @option opts [Boolean] :blank_passwords See {#blank_passwords}
  # @option opts [String] :pass_file See {#pass_file}
  # @option opts [String] :password See {#password}
  # @option opts [Array<Credential>] :prepended_creds ([]) See {#prepended_creds}
  # @option opts [Boolean] :user_as_pass See {#user_as_pass}
  # @option opts [String] :user_file See {#user_file}
  # @option opts [String] :username See {#username}
  # @option opts [String] :userpass_file See {#userpass_file}
  def initialize(opts = {})
    opts.each do |attribute, value|
      public_send("#{attribute}=", value)
    end
    self.prepended_creds ||= []
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

  # Combines all the provided credential sources into a stream of {Credential}
  # objects, yielding them one at a time
  #
  # @yieldparam credential [Metasploit::Framework::Credential]
  # @return [void]
  def each
    if pass_file.present?
      pass_fd = File.open(pass_file, 'r:binary')
    end

    prepended_creds.each { |c| yield c }

    if username.present?
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
    end

    if user_file.present?
      File.open(user_file, 'r:binary') do |user_fd|
        user_fd.each_line do |user_from_file|
          user_from_file.chomp!
          if password
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

  ensure
    pass_fd.close if pass_fd && !pass_fd.closed?
  end

  private

  def private_type(private)
    if private =~ /[0-9a-f]{32}:[0-9a-f]{32}/
      :ntlm_hash
    else
      :password
    end
  end

end
