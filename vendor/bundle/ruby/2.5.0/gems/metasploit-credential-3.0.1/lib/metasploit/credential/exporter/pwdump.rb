require 'erb'

# Exports {Metasploit::Credential::Login Metasploit::Credential::Logins} in the old pwdump format.
#
# # Service
#
# The service for a given login is in comment (`#`) above the login in the format
# '`Mdm::Host#address`:`Mdm::Service#port`/`Mdm::Service#proto` (`Mdm::Service#name`)'
#
# # Logins
#
# There is one {Metasploit::Credential::Login} per line with the line format varying based on the `Class` of
# {Metasploit::Credential::Login#core} {Metasploit::Credential::Core#private}.
#
# * {Metasploit::Credential::Public#username}:{Metasploit::Credential::NonreplayableHash#data}:::
# * {Metasploit::Credential::Public#username}:{Metasploit::Credential::Login#id}:{Metasploit::Credential::NTLMHash#data}
# * {Metasploit::Credential::Public#username} {Metasploit::Credential::Password#data}
#
# ## Blanks
#
# If the username or password is blank, then {BLANK_CRED_STRING} is used instead of an empty string.
#
# The full format is as follows:
#
#     #
#     # Metasploit PWDump: <version>
#     # Generated: <UTC Time>
#     # Project: <Mdm::Workspace#name>
#     #
#     #########################################################
#
#     #  LM/NTLM Hashes (<Metasploit::Credential::NTLMHash count> hashes, <Metasploit::Credential::NTLMHash service count> services)
#
#     # <Mdm::Host#address>:<Mdm::Service#port>/<Mdm::Service#proto> (<Mdm::Service#name>)
#     <Metasploit::Credential::Public#username>:<Metasploit::Credential::Login#id>:<Metasploit::Credential::NTLMHash#data>
#
#
#     #  Hashes (<Metasploit::Credential::Nonreplayable count> hashes, <Metasploit::Credential::Nonreplayable service count> services)
#
#     # <Mdm::Host#address>:<Mdm::Service#port>/<Mdm::Service#proto> (<Mdm::Service#name>)
#     <Metasploit::Credential::Public#username>:<Metasploit::Credential::NonreplayableHash#data>:::
#
#     #  Plaintext Passwords (<Metasploit::Credential::Password count> passwords, <Metasploit::Credential::Password service count> services)
#
#     # <Mdm::Host#address>:<Mdm::Service#port>/<Mdm::Service#proto> (<Mdm::Service#name>)
#     <Metasploit::Credential::Public#username> <Metasploit::Credential::Password#data>
#
#
class Metasploit::Credential::Exporter::Pwdump
  include Metasploit::Credential::Exporter::Base

  #
  # Constants
  #

  # The string inserted when either the public or private half of a credential is blank
  BLANK_CRED_STRING = '<BLANK>'

  # Used to check for this file type when importing/parsing
  FILE_ID_STRING = "# Metasploit PWDump Export"

  # Where the MSF pwdump template lives
  TEMPLATE_PATH = File.expand_path(File.join(File.dirname(__FILE__), "pwdump_template.erb"))

  # The version of the export format
  VERSION = "2.0"


  #
  # Attributes
  #

  # @!attribute [rw] logins
  #   Holds the raw information from the database before it is formatted into the {#data} attribute
  #   @return [Array<Metasploit::Credential::Login>]
  attr_writer :logins


  #
  # Instance Methods
  #

  def data
    unless instance_variable_defined? :@data
      @data = {}
      @data[:ntlm]           = logins.select{ |l| l.core.private.present? && l.core.private.is_a?(Metasploit::Credential::NTLMHash) }
      @data[:non_replayable] = logins.select{ |l| l.core.private.present? && l.core.private.is_a?(Metasploit::Credential::NonreplayableHash) }
      @data[:password]       = logins.select{ |l| l.core.private.present? && l.core.private.is_a?(Metasploit::Credential::Password) }
      @data[:postgres_md5]   = logins.select{ |l| l.core.private.present? && l.core.private.is_a?(Metasploit::Credential::PostgresMD5) }
    end
    @data
  end

  # The collection of {Metasploit::Credential::Login} objects that will get parsed for output in the export
  # @return [ActiveRecord::Relation]
  def logins
    @logins ||= Metasploit::Credential::Login.in_workspace_including_hosts_and_services(workspace)
  end

  # Format a {Metasploit::Credential::Public} and a {Metasploit::Credential::NonReplayableHash} for output
  # @param login [Metasploit::Credential::Login]
  # @return [String]
  def format_nonreplayable_hash(login)
    creds_data = data_for_login(login)
    username = Metasploit::Credential::Text.ascii_safe_hex(creds_data[:username])
    hash     = Metasploit::Credential::Text.ascii_safe_hex(creds_data[:private_data])
    "#{username}:#{hash}:::"
  end

  # Format a {Metasploit::Credential::Public} and a {Metasploit::Credential::NTLMHash} for output
  # @param login [Metasploit::Credential::Login]
  # @return [String]
  def format_ntlm_hash(login)
    creds_data = data_for_login(login)
    "#{creds_data[:username]}:#{login.id}:#{creds_data[:private_data]}:::"
  end

  # Format a {Metasploit::Credential::Public} and a {Metasploit::Credential::Password} for output
  # @param login [Metasploit::Credential::Login]
  # @return [String]
  def format_password(login)
    creds_data = data_for_login(login)
    "#{creds_data[:username]} #{creds_data[:private_data]}"
  end

  # Format a {Metasploit::Credential::Public} and a {Metasploit::Credential::PostgresMD5} for output
  # @param login [Metasploit::Credential::Login]
  # @return [String]
  def format_postgres_md5(login)
    creds_data = data_for_login(login)
    "#{creds_data[:username]}:#{creds_data[:private_data]}"
  end

  # Returns a string for the host/service/port/proto/service name combination in the pwdump file.
  # This string is added to make it easier for a human to scan the file.
  # @param login [Metasploit::Credential::Login] the login to look at
  # @return [String]
  def format_service_for_login(login)
    service = login.service
    address = service.host.address.to_s
    "#{address}:#{service.port}/#{service.proto} (#{service.name})"
  end

  # Renders the collection credential objects in {#data} into the `ERB` template at {TEMPLATE_PATH}
  # @return [String]
  def rendered_output
    @version_string = VERSION
    @workspace      = workspace
    template        = ERB.new(File.read TEMPLATE_PATH)
    template.result get_binding
  end

  # Returns the count of services in the group creds contained in +hash_array+
  # @param hash_array [Array<Metasploit::Credential::Login>]
  # @return [Fixnum]
  def service_count_for_hashes(hash_array)
    hash_array.collect(&:service).collect(&:id).uniq.size
  end

  private

  # Returns a hash containing the public and private or the canonical blank string
  # @param login [Metasploit::Credential::Login]
  # @return [Hash]
  def data_for_login(login)
    public  = login.core.try(:public)
    private = login.core.try(:private)

    username     = public.present? && public.username.present? ? public.username : BLANK_CRED_STRING
    private_data = private.present? && private.data.present? ? private.data : BLANK_CRED_STRING
    {
      username: username,
      private_data: private_data
    }
  end

  def get_binding
    binding.dup
  end
end
