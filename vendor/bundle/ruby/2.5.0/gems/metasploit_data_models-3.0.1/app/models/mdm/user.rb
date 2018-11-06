# A user of metasploit-framework or metasploit-pro.
class Mdm::User < ActiveRecord::Base
  extend MetasploitDataModels::SerializedPrefs
  
  #
  # Associations
  #

  # Automatic exploitation runs started by this user.
  has_many :automatic_exploitation_runs,
           class_name: 'MetasploitDataModels::AutomaticExploitation::Run',
           inverse_of: :user

  # Automatic exploitation match sets created by this user for {#automatic_exploitation_runs}.
  has_many :automatic_exploitation_match_sets,
           class_name: 'MetasploitDataModels::AutomaticExploitation::MatchSet',
           inverse_of: :user

  # {Mdm::Workspace Workspaces} owned by this user.  Owned workspaces allow user complete permissions without the need
  # or the user to be an {#admin administrator}.
  has_many :owned_workspaces,
           class_name: 'Mdm::Workspace',
           foreign_key: 'owner_id',
           inverse_of: :owner

  # Runs of Metasploit Modules by this user.
  has_many :module_runs,
           class_name: 'MetasploitDataModels::ModuleRun',
           inverse_of: :user

  # Tags created by the user.
  has_many :tags,
           class_name: 'Mdm::Tag',
           inverse_of: :user

  # {Mdm::Workspace Workspace} where this user has access.  If a user is an {#admin administrator} they have access
  # to all workspaces even if they are not a member of that workspace.
  has_and_belongs_to_many :workspaces,
                          -> { uniq },
                          class_name: 'Mdm::Workspace',
                          join_table: 'workspace_members'

  #
  # Attributes
  #

  # @!attribute admin
  #   Whether this user is an administrator.  Administrator permissions are only enforced in metasploit-pro through the
  #   controllers.
  #
  #   @return [false] if this is a normal user that must be added to each workspace.
  #   @return [true] if this user is an administrator and have access to all workspaces without being added to the
  #     workspace explicitly.  User is also allowed to add other users to workspaces or make other users admins.

  # @!attribute company
  #   Company at which user works.
  #
  #   @return [String, nil]

  # @!attribute created_at
  #   When the user was created.
  #
  #   @return [DateTime]

  # @!attribute crypted_password
  #   Hashed password (salted with {#password_salt}) by Authlogic in metasploit-pro.
  #
  #   @return [String]

  # @!attribute email
  #   The user's email address.
  #
  #   @return [String, nil]

  # @!attribute fullname
  #   The user's normal human name.
  #
  #   @return [String, nil]

  # @!attribute password_salt
  #   Salt used when hashing password into {#crypted_password} by Authlogic in metasploit-pro.
  #
  #   @return [String]

  # @!attribute persistence_token
  #   Token used for session and cookie when user is logged using Authlogic in metasploit-pro.
  #
  #   @return [String]

  # @!attribute phone
  #   Phone number for user.
  #
  #   @return [String, nil]

  # @!attribute updated_at
  #   When the user was last updated.
  #
  #   @return [DateTime]

  # @!attribute username
  #   Username for this user.  Used to log into metasploit-pro.
  #
  #   @return [String]

  #
  # Serialziations
  #

  # Hash of user preferences
  #
  # @return [Hash]
  serialize :prefs, MetasploitDataModels::Base64Serializer.new

  # @!attribute time_zone
  #   User's preferred time zone.
  #
  #   @return [String, nil]
  serialized_prefs_attr_accessor :time_zone

  #
  #  @!group Duplicate Login Monitoring
  #

  # @!attribute last_login_address
  #   @note specifically NOT last_login_ip to prevent confusion with AuthLogic magic columns (which dont work for
  #     serialized fields)
  #
  #   Last IP address from which this user logged in.  Used to report currently active user session's IP when the user
  #   is logged off because theire `session[:session_id]` does not match {#session_key}.
  #
  #   @return [String, nil]
  serialized_prefs_attr_accessor :last_login_address

  # @!attribute session_key
  #   Holds `session[:session_id]` so user can only be logged in once.  Only enforced in metasploit-pro.
  #
  #   @return [String, nil]
  serialized_prefs_attr_accessor :session_key

  #
  # @!endgroup
  #

  #
  # @!group HTTP Proxy
  #

  # @!attribute http_proxy_host
  #   Proxy host.
  #
  #   @return [String, nil]
  serialized_prefs_attr_accessor :http_proxy_host

  # @!attribute http_proxy_pass
  #   Password used to login as {#http_proxy_user} to proxy.
  #
  #   @return [String, nil]
  serialized_prefs_attr_accessor :http_proxy_pass

  # @!attribute http_proxy_port
  #   Port on which proxy run on {#http_proxy_host}.
  #
  #   @return [String, Integer, nil]
  serialized_prefs_attr_accessor :http_proxy_port

  # @!attribute http_proxy_user
  #   User used to log into proxy.
  #
  #   @return [String, nil]
  serialized_prefs_attr_accessor :http_proxy_user

  #
  # @!endgroup
  #

  #
  # @!group Nexpose
  #

  # @!attribute nexpose_host
  #   Host name for server running Nexpose.
  #
  #   @return [String, nil]
  serialized_prefs_attr_accessor :nexpose_host

  # @!attribute nexpose_pass
  #   Password to log into Nexpose.
  #
  #   @return [String, nil]
  serialized_prefs_attr_accessor :nexpose_pass

  # @!attribute nexpose_port
  #   Port on {#nexpose_host} on which Nexpose is running.
  #
  #   @return [String, Integer. nil]
  serialized_prefs_attr_accessor :nexpose_port

  # @!attribute nexpose_user
  #   User used to log into Nexpose.
  #
  #   @return [String, nil]
  serialized_prefs_attr_accessor :nexpose_user

  #
  # @!endgroup
  #

  #
  # @!group Nexpose Authenticated Scan Credentials
  #

  # @!attribute nexpose_creds_pass
  #   @return [String, nil]
  serialized_prefs_attr_accessor :nexpose_creds_pass

  # @!attribute nexpose_creds_type
  #   @return [String, nil]
  serialized_prefs_attr_accessor :nexpose_creds_type

  # @!attribute nexpose_creds_user
  #   @return [String, nil]
  serialized_prefs_attr_accessor :nexpose_creds_user

  #
  # @!endgroup
  #

  Metasploit::Concern.run(self)
end

