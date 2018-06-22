require 'sysrandom/securerandom'

module Msf::DBManager::User

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
  # Report a user's attributes
  #
  # The opts parameter MUST contain
  # +:XXX+::         -- the users's XXX
  #
  # The opts parameter can contain:
  # +:XXX+::        -- XXX
  #
  def report_user(opts)
    return if !active

    # TODO: implement method
    raise 'Msf::DBManager::User#report_user is not implemented'
  end

  def update_user(opts)
    ::ActiveRecord::Base.connection_pool.with_connection {
      # process workspace string for update if included in opts
      wspace = Msf::Util::DBManager.process_opts_workspace(opts, framework, false)
      opts[:workspace] = wspace if wspace

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
  # @return [Boolean] true if the user is successfully authenticated; otherwise, false.
  def authenticate_user(opts)
    raise ArgumentError.new("The following options are required: :id") if opts[:id].nil?
    raise ArgumentError.new("The following options are required: :password") if opts[:password].nil?

    user = Mdm::User.find(opts[:id])
    # TODO: Yes, we need proper password salting and hashing here
    if !user.nil? && user.crypted_password == opts[:password]
      true
    else
      false
    end
  end

  # Creates a new API token for the user.
  #
  # @param opts[:ids] [Integer] ID for the user.
  # @return [String] The new API token.
  def create_new_user_token(opts)
    raise ArgumentError.new("The following options are required: :id") if opts[:id].nil?

    token_length = opts[:token_length] || 20
    # NOTE: repurposing persistence_token in the database as the API token
    Mdm::User.update(opts[:id], {persistence_token: SecureRandom.hex(token_length)}).persistence_token
  end
end
