# Implements importation behavior for pwdump files exported by Metasploit as well as files from the John the Ripper
# hash cracking suite: http://www.openwall.com/john/
#
# Please note that in the case of data exported from Metasploit, the dataset will contain information on the `Mdm::Host`
# and `Mdm::Service` objects that are related to the credential.  This means that Metasploit exports will be limited to
# containing {Metasploit::Credential::Login} objects, which is the legacy behavior of this export prior to the creation
# of this library.
class Metasploit::Credential::Importer::Pwdump
  include Metasploit::Credential::Importer::Base
  include Metasploit::Credential::Creation

  #
  # Constants
  #

  # Matches a line starting with a '#'
  COMMENT_LINE_START_REGEX     = /^[\s]*#/

  # The string that John the Ripper uses to designate a lack of password in a credentials entry
  JTR_NO_PASSWORD_STRING = "NO PASSWORD"

  # Matches lines that contain usernames and non-SMB hashes
  NONREPLAYABLE_REGEX               = /^[\s]*([\x21-\x7f]+):([\x21-\x7f]+):::/n

  # Matches lines that contain usernames and plaintext passwords
  PLAINTEXT_REGEX                   = /^[\s]*([\x21-\x7f]+)[\s]+([\x21-\x7f]+)?/n

  # Matches lines taht contain MD5 hashes for PostgreSQL
  POSTGRES_REGEX                    = /^[\s]*([\x21-\x7f]+):md5([0-9a-f]{32})$/

  # Matches a line that we use to get information for creating `Mdm::Host` and `Mdm::Service` objects
  # TODO: change to use named groups from 1.9+
  SERVICE_COMMENT_REGEX             = /^#[\s]*([0-9.]+):([0-9]+)(\x2f(tcp|udp))?[\s]*(\x28([^\x29]*)\x29)?/n

  # Matches the way that John the Ripper exports SMB hashes with no password piece
  SMB_WITH_JTR_BLANK_PASSWORD_REGEX = /^[\s]*([^\s:]+):([0-9]+):NO PASSWORD\*+:NO PASSWORD\*+[^\s]*$/

  # Matches LM/NTLM hash format
  SMB_WITH_HASH_REGEX               = /^[\s]*([^\s:]+):[0-9]+:([A-Fa-f0-9]+:[A-Fa-f0-9]+):[^\s]*$/

  # Matches a line with free-form text - less restrictive than {SMB_WITH_HASH_REGEX}
  SMB_WITH_PLAINTEXT_REGEX          = /^[\s]*([^\s:]+):(.+):[A-Fa-f0-9]*:[A-Fa-f0-9]*:::$/

  # Matches warning lines in legacy pwdump files
  WARNING_REGEX                     = /^[\s]*Warning:/

  #
  # Validations
  #

  validates :filename, presence: true

  #
  # Instance Methods
  #

  # Checks a string for matching {Metasploit::Credential::Exporter::Pwdump::BLANK_CRED_STRING} and returns blank string
  # if it matches that constant.
  # @param check_string [String] the string to check
  # @param dehex [Boolean] convert hex to char if true
  # @return [String]
  def blank_or_string(check_string, dehex=false)
    if check_string.blank? || check_string ==  Metasploit::Credential::Exporter::Pwdump::BLANK_CRED_STRING || check_string == JTR_NO_PASSWORD_STRING
      ""
    else
      if dehex
        Metasploit::Credential::Text.dehex check_string
      else
        check_string
      end
    end
  end

  # Perform the import of the credential data, creating `Mdm::Host` and `Mdm::Service` objects as needed,
  # parsing out data by matching against regex constants that match the various kinds of valid lines found
  # in the file.  Ignore lines which match none of the REGEX constants.
  # @return [void]
  def import!
    service_info = nil
    Metasploit::Credential::Core.transaction do
      input.each_line do |line|
        case line
          when WARNING_REGEX
            next
          when COMMENT_LINE_START_REGEX
            service_info = service_info_from_comment_string(line)
          when SMB_WITH_HASH_REGEX
            info = parsed_regex_results($1, $2)
            username, private = info[:username], info[:private]
            creds_class = Metasploit::Credential::NTLMHash
          when SMB_WITH_JTR_BLANK_PASSWORD_REGEX
            info = parsed_regex_results($1, $2)
            username, private = info[:username], info[:private]
            creds_class = Metasploit::Credential::NTLMHash
          when SMB_WITH_PLAINTEXT_REGEX
            info = parsed_regex_results($1, $2)
            username, private = info[:username], info[:private]
            creds_class = Metasploit::Credential::NTLMHash
          when NONREPLAYABLE_REGEX
            info = parsed_regex_results($1, $2)
            username, private = info[:username], info[:private]
            creds_class = Metasploit::Credential::NonreplayableHash
          when POSTGRES_REGEX
            info = parsed_regex_results($1,"md5#{$2}")
            username, private = info[:username], info[:private]
            creds_class = Metasploit::Credential::PostgresMD5
          when PLAINTEXT_REGEX
            info = parsed_regex_results($1, $2, true)
            username, private = info[:username], info[:private]
            creds_class = Metasploit::Credential::Password
          else
            next
        end

        # Skip unless we have enough to make a Login
        if service_info.present?
          if [service_info[:host_address], service_info[:port], username, private].compact.size != 4
            next
          end
        else
          next
        end

        public_obj = create_credential_public(username: username)

        private_obj = creds_class.where(data: private).first_or_create

        core   = create_credential_core(origin: origin, private: private_obj, public: public_obj, workspace_id: workspace.id)

        login_opts = {
          address:      service_info[:host_address],
          port:         service_info[:port],
          protocol:     service_info[:protocol],
          service_name: service_info[:name],
          workspace_id: workspace.id,
          core:         core,
          status: Metasploit::Model::Login::Status::UNTRIED
        }

        create_credential_login(login_opts)
      end
    end
  end

  def initialize(args={})
    super args
  end

  # Break a line into user, hash
  # @param username [String]
  # @param private [String]
  # @param dehex [Boolean] convert hex to char if true
  # @return [Hash]
  def parsed_regex_results(username, private, dehex=false)
    results = {}
    results[:username] = blank_or_string(username, dehex)
    results[:private]  = blank_or_string(private, dehex)

    results
  end

  # Take an msfpwdump comment string and parse it into information necessary for
  # creating `Mdm::Host` and `Mdm::Service` objects.
  # @param comment_string [String] a string starting with a '#' that conforms to {SERVICE_COMMENT_REGEX}
  # @return [Hash]
  def service_info_from_comment_string(comment_string)
    service_info = {}
    if comment_string[SERVICE_COMMENT_REGEX]
      service_info[:host_address]  = $1
      service_info[:port]          = $2
      service_info[:protocol]      = $4.present? ? $4 : "tcp"
      service_info[:name]          = $6
      service_info
    else
      nil
    end
  end

end
