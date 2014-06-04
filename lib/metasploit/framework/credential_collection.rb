require 'metasploit/framework/credential'

class Metasploit::Framework::CredentialCollection

  attr_accessor :blank_passwords
  attr_accessor :pass_file
  attr_accessor :password
  attr_accessor :user_as_pass
  attr_accessor :user_file
  attr_accessor :username
  attr_accessor :userpass_file

  # @option opts [Boolean] :blank_passwords Whether each username should be tried with a blank password
  # @option opts [String] :pass_file Path to a file containing passwords, one per line
  # @option opts [String] :password
  # @option opts [Boolean] :user_as_pass Whether each username should be tried as a password for that user
  # @option opts [String] :user_file Path to a file containing usernames, one per line
  # @option opts [String] :username
  # @option opts [String] :userpass_file Path to a file containing usernames and passwords seperated by a space, one pair per line
  def initialize(opts = {})
    opts.each do |attribute, value|
      public_send("#{attribute}=", value)
    end
  end

  # @yieldparam credential [Metasploit::Framework::Credential]
  # @return [void]
  def each
    if pass_file
      pass_fd = File.open(pass_file, 'r:binary')
    end

    if username
      if password
        yield Metasploit::Framework::Credential.new(public: username, private: password)
      end
      if user_as_pass
        yield Metasploit::Framework::Credential.new(public: username, private: username)
      end
      if blank_passwords
        yield Metasploit::Framework::Credential.new(public: username, private: "")
      end
      if pass_fd
        pass_fd.each_line do |pass_from_file|
          yield Metasploit::Framework::Credential.new(public: username, private: pass_from_file)
        end
        pass_fd.seek(0)
      end
    end

    if user_file
      File.open(user_file, 'r:binary') do |user_fd|
        user_fd.each_line do |user_from_file|
          if password
            yield Metasploit::Framework::Credential.new(public: user_from_file, private: password)
          end
          if user_as_pass
            yield Metasploit::Framework::Credential.new(public: user_from_file, private: user_from_file)
          end
          if blank_passwords
            yield Metasploit::Framework::Credential.new(public: user_from_file, private: "")
          end
          if pass_fd
            pass_fd.each_line do |pass_from_file|
              yield Metasploit::Framework::Credential.new(public: user_from_file, private: pass_from_file)
            end
            pass_fd.seek(0)
          end
        end
      end
    end
  end

end
