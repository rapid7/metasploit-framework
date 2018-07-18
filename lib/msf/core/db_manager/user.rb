require 'bcrypt'
require 'sysrandom/securerandom'

module Msf::DBManager::User

  MIN_TOKEN_LENGTH = 20

  # Returns a list of all users in the database
  def users(opts)
    ::ActiveRecord::Base.connection_pool.with_connection {

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
  # @return [Mdm::User] The reported Mdm::User object.
  def report_user(opts)
    return unless active
    raise ArgumentError.new("Missing required option :username") if opts[:username].nil?
    raise ArgumentError.new("Missing required option :password") if opts[:password].nil?

    ::ActiveRecord::Base.connection_pool.with_connection {

      conditions = {username: opts[:username]}
      user = Mdm::User.where(conditions).first_or_initialize

      opts.each do |k,v|
        if user.attribute_names.include?(k.to_s)
          user[k] = v
        elsif !v.blank?
          dlog("Unknown attribute for ::Mdm::User: #{k}")
        end
      end

      user.crypted_password = BCrypt::Password.create(opts[:password])
      user.admin = false if opts[:admin].nil?

      # Finalize
      if user.changed?
        msf_import_timestamps(opts, user)
        user.save!
      end

      user
    }
  end

  # Update the attributes of a user entry with the values in opts.
  # The values in opts should match the attributes to update.
  #
  # @param opts [Hash] Hash containing the updated values. Key should match the attribute to update. Must contain :id of record to update.
  # @return [Mdm::User] The updated Mdm::User object.
  def update_user(opts)
    ::ActiveRecord::Base.connection_pool.with_connection {
      id = opts.delete(:id)
      Mdm::User.update(id, opts)
    }
  end

  # Deletes user entries based on the IDs passed in.
  #
  # @param opts[:ids] [Array] Array containing Integers corresponding to the IDs of the user entries to delete.
  # @return [Array] Array containing the Mdm::User objects that were successfully deleted.
  def delete_user(opts)
    raise ArgumentError.new("The following options are required: :ids") if opts[:ids].nil?

    ::ActiveRecord::Base.connection_pool.with_connection {
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
  # @param opts[:ids] [Integer] ID of the user to authenticate.
  # @param opts[:password] [String] The user's password.
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
  # The opts parameter MUST contain:
  # @param opts[:ids] [Integer] ID for the user.
  #
  # The opts parameter can contain:
  # @param opts[:token_length] [Integer] Token length.
  #
  # @return [String] The new API token.
  def create_new_user_token(opts)
    raise ArgumentError.new("The following options are required: :id") if opts[:id].nil?

    token_length = opts[:token_length] || MIN_TOKEN_LENGTH
    # NOTE: repurposing persistence_token in the database as the API token
    Mdm::User.update(opts[:id], {persistence_token: SecureRandom.hex(token_length)}).persistence_token
  end

end
