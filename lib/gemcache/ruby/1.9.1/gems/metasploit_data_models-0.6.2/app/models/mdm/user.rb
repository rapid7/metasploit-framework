class Mdm::User < ActiveRecord::Base
  extend MetasploitDataModels::SerializedPrefs

  #
  # Relations
  #

  has_many :owned_workspaces, :foreign_key => 'owner_id', :class_name => 'Mdm::Workspace'
  has_many :tags, :class_name => 'Mdm::Tag'
  has_and_belongs_to_many :workspaces, :join_table => 'workspace_members', :uniq => true, :class_name => 'Mdm::Workspace'

  #
  # Serialziations
  #

  serialize :prefs, MetasploitDataModels::Base64Serializer.new

  serialized_prefs_attr_accessor :nexpose_host, :nexpose_port, :nexpose_user, :nexpose_pass, :nexpose_creds_type, :nexpose_creds_user, :nexpose_creds_pass
  serialized_prefs_attr_accessor :http_proxy_host, :http_proxy_port, :http_proxy_user, :http_proxy_pass
  serialized_prefs_attr_accessor :time_zone, :session_key
  serialized_prefs_attr_accessor :last_login_address # specifically NOT last_login_ip to prevent confusion with AuthLogic magic columns (which dont work for serialized fields)

  ActiveSupport.run_load_hooks(:mdm_user, self)
end

