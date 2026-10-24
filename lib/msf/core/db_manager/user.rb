require 'securerandom'

module Msf::DBManager::User

  MIN_TOKEN_LENGTH = 20

  # Attributes of an Mdm::User that callers such as the web service may set. Any other key is ignored.
  # persistence_token, which is the API token, must only be minted server-side by #create_new_user_token,
  # and crypted_password is derived from :password by #report_user rather than accepted directly.
  USER_ATTRIBUTES = %w[username fullname email phone company prefs admin].freeze

  # Attributes that may additionally be set when restoring a user from trusted data (see
  # #msf_import_user), so that API tokens and SSO settings survive an import.
  TRUSTED_USER_ATTRIBUTES = (USER_ATTRIBUTES + %w[sso_enabled persistence_token password_salt]).freeze

  # Returns a list of all users in the database
  def users(opts)
    ::ApplicationRecord.connection_pool.with_connection {

      opts = opts.clone() # protect the original caller's opts
      search_term = opts.delete(:search_term)
      if search_term && !search_term.empty?
        column_search_conditions = Msf::Util::DBManager.create_all_column_search_conditions(Mdm::User, search_term)
        Mdm::User.where(opts).where(column_search_conditions)
      else
        Mdm::User.where(opts)
      end
    }
  end

  #
  # Report a user's attributes.
  #
  # The opts parameter MUST contain:
  # +:username+:: -- the username
  # +:password+:: -- the users's cleartext password
  #
  # The opts parameter can contain:
  # +:fullname+:: -- the users's fullname
  # +:email+::    -- the users's email
  # +:phone+::    -- the users's phone
  # +:email+::    -- the users's email
  # +:company+::  -- the users's company
  # +:prefs+::    -- [Hash] the users's preferences
  # +:admin+::    -- [Boolean] True if the user is an admin; otherwise, false.
  #
  # Only the attributes in USER_ATTRIBUTES are used; any other key is ignored. Callers restoring a user
  # from trusted data can pass +true+ as the second argument to also set the attributes in
  # TRUSTED_USER_ATTRIBUTES. Never do that for data that comes from a web service request.
  #
  # @param opts [Hash] The user's attributes. Bare keywords are accepted, e.g. +report_user(username: 'u', password: 'p')+.
  # @param trusted [Boolean] True to also accept the attributes in TRUSTED_USER_ATTRIBUTES. This is a separate
  #   argument rather than a key of +opts+ so that it can never be switched on by request data.
  # @return [Mdm::User] The reported Mdm::User object.
  def report_user(opts, trusted = false)
    return unless active
    raise ArgumentError.new("Missing required option :username") if opts[:username].nil?
    raise ArgumentError.new("Missing required option :password") if opts[:password].nil?

    ::ApplicationRecord.connection_pool.with_connection {

      conditions = {username: opts[:username]}
      user = Mdm::User.where(conditions).first_or_initialize

      allowed_attributes = trusted ? TRUSTED_USER_ATTRIBUTES : USER_ATTRIBUTES
      opts.each do |k,v|
        if allowed_attributes.include?(k.to_s)
          user[k] = v
        elsif !v.blank?
          dlog("Ignoring attribute that cannot be set for ::Mdm::User: #{k}")
        end
      end

      user.crypted_password = BCrypt::Password.create(opts[:password])
      user.admin = false if opts[:admin].nil?

      # Finalize
      if user.changed?
        msf_assign_timestamps(opts, user)
        user.save!
      end

      user
    }
  end

  # Update the attributes of a user entry with the values in opts.
  # The values in opts should match the attributes to update. Only the attributes in USER_ATTRIBUTES
  # are updated; any other key is ignored.
  #
  # @param opts [Hash] Hash containing the updated values. Key should match the attribute to update. Must contain :id of record to update.
  # @return [Mdm::User] The updated Mdm::User object.
  def update_user(opts)
    ::ApplicationRecord.connection_pool.with_connection {
      opts = opts.clone() # protect the original caller's opts
      id = opts.delete(:id)
      user = Mdm::User.find(id)

      attributes, ignored = opts.partition { |k, _v| USER_ATTRIBUTES.include?(k.to_s) }.map(&:to_h)
      ignored.each_key { |k| dlog("Ignoring attribute that cannot be updated for ::Mdm::User: #{k}") }
      user.update!(attributes)
      return user
    }
  end

  # Deletes user entries based on the IDs passed in.
  #
  # @param opts[:ids] [Array] Array containing Integers corresponding to the IDs of the user entries to delete.
  # @return [Array] Array containing the Mdm::User objects that were successfully deleted.
  def delete_user(opts)
    raise ArgumentError.new("The following options are required: :ids") if opts[:ids].nil?

    ::ApplicationRecord.connection_pool.with_connection {
      deleted = []
      opts[:ids].each do |user_id|
        user = Mdm::User.find(user_id)
        begin
          deleted << user.destroy
        rescue # refs suck
          elog("Forcibly deleting #{user}")
          deleted << user.delete
        end
      end

      return deleted
    }
  end

  # Authenticates the user.
  #
  # @param opts [Hash] Options hash.
  # @option opts [Integer] :id ID of the user to authenticate.
  # @option opts [String] :password The user's password.
  # @return [Boolean] True if the user is successfully authenticated; otherwise, false.
  def authenticate_user(opts)
    raise ArgumentError.new("The following options are required: :id") if opts[:id].nil?
    raise ArgumentError.new("The following options are required: :password") if opts[:password].nil?

    user = Mdm::User.find(opts[:id])
    begin
      !user.nil? && BCrypt::Password.new(user.crypted_password) == opts[:password]
    rescue BCrypt::Errors::InvalidHash
      false
    end
  end

  # Creates a new API token for the user.
  #
  # @param opts [Hash] Options hash.
  # @option opts [Integer] :id ID for the user (required).
  # @option opts [Integer] :token_length Token length (optional).
  #
  # @return [String] The new API token.
  def create_new_user_token(opts)
    raise ArgumentError.new("The following options are required: :id") if opts[:id].nil?

    token_length = opts[:token_length] || MIN_TOKEN_LENGTH
    # NOTE: repurposing persistence_token in the database as the API token
    user = Mdm::User.find(opts[:id])
    user.update!({persistence_token: SecureRandom.hex(token_length)})
    user.persistence_token
  end

end
