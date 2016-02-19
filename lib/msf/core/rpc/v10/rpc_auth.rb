# -*- coding: binary -*-
module Msf
module RPC
class RPC_Auth < RPC_Base

# Dynamic load test for SHA2 (needed for SHA512)
@@loaded_sha2 = false
begin
  require 'digest/sha2'
  @@loaded_sha2 = true
rescue ::LoadError
end

  # Handles client authentication. The authentication token will expire 5 minutes after the
  # last request was made.
  #
  # @param [String] user The username.
  # @param [String] pass The password.
  # @raise [Msf::RPC::Exception] Something is wrong while authenticating, you can possibly get:
  #                              * 401 Failed authentication.
  # @return [Hash] A hash indicating a successful login, it contains the following keys:
  #  * 'result' [String] A successful message: 'success'.
  #  * 'token' [String] A token for the authentication.
  # @example Here's how you would use this from the client:
  #  # This returns something like the following:
  #  # {"result"=>"success", "token"=>"TEMPyp1N40NK8GM0Tx7A87E6Neak2tVJ"}
  #  rpc.call('auth.login_noauth', 'username', 'password')
  def rpc_login_noauth(user,pass)
    if not (user.kind_of?(::String) and pass.kind_of?(::String))
      error(401, "Login Failed")
    end

    # handle authentication here
    fail = true
    self.users.each do |u|
      if(u[0] == user and u[1] == pass)
        fail = false
        break
      end
    end

    fail = db_validate_auth(user,pass) if fail

    if fail
      # Introduce a random delay in the response to annoy brute forcers
      delay = [ ( rand(3000) / 1000.0 ), 0.50 ].max
      ::IO.select(nil, nil, nil, delay)

      # Send back a 401 denied error
      error(401, "Login Failed")
    end

    token = "TEMP" + Rex::Text.rand_text_alphanumeric(28)
    self.service.tokens[token] = [user, Time.now.to_i, Time.now.to_i]
    { "result" => "success", "token" => token }
  end


  # Handles client deauthentication.
  #
  # @param [String] token The user's token to log off.
  # @raise [Msf::RPC::Exception] An error indicating a failed deauthentication, including:
  #                              * 500 Invalid authentication token.
  #                              * 500 Permanent authentication token.
  # @return [Hash] A hash indiciating the action was successful. It contains the following key:
  #  * 'result' [String] The successful message: 'success'
  # @example Here's how you would use this from the client:
  #  # This returns something like:
  #  # {"result"=>"success"}
  #  rpc.call('auth.logout', 'TEMPyp1N40NK8GM0Tx7A87E6Neak2tVJ')
  def rpc_logout(token)
    found = self.service.tokens[token]
    error("500", "Invalid Authentication Token") if not found
    error("500", "Permanent Authentication Token") if found[3] == true

    # Delete the token if its not marked as permanent
    self.service.tokens.delete(token)

    { "result" => "success" }
  end


  # Returns a list of authentication tokens, including the ones that are
  # temporary, permanent, or stored in the backend.
  #
  # @return [Hash] A hash that contains a list of authentication tokens. It contains the following key:
  #  * 'tokens' [Array<string>] An array of tokens.
  # @example Here's how you would use this from the client:
  #  # This returns something like:
  #  # {"tokens"=>["TEMPf5I4Ec8cBEKVD8D7xtIbTXWoKapP", "TEMPtcVmMld8w74zo0CYeosM3iXW0nJz"]}
  #  rpc.call('auth.token_list')
  def rpc_token_list
    res = self.service.tokens.keys
    begin
      if framework.db and framework.db.active
        ::Mdm::ApiKey.all.each do |k|
          res << k.token
        end
      end
    rescue ::Exception
    end
    { "tokens" => res }
  end


  # Adds a new token to the database.
  #
  # @param [String] token A unique token.
  # @return [Hash] A hash indicating the action was successful. It contains the following key:
  #  * 'result' [String] The successful message: 'success'
  # @example Here's how you would use this from the client:
  #  rpc.call('auth.token_add', 'UNIQUE_TOKEN')
  def rpc_token_add(token)
    db = false
    begin
      if framework.db and framework.db.active
        t = ::Mdm::ApiKey.new
        t.token = token
        t.save!
        db = true
      end
    rescue ::Exception
    end

    if not db
      self.service.tokens[token] = [nil, nil, nil, true]
    end

    { "result" => "success" }
  end


  # Generates a random 32-byte authentication token. The token is added to the
  # database as a side-effect.
  #
  # @return [Hash] A hash indicating the action was successful, also the new token.
  #  It contains the following keys:
  #  * 'result' [String] The successful message: 'success'
  #  * 'token' [String] A new token.
  # @example Here's how you would use this from the client:
  #  rpc.call('auth.token_generate')
  def rpc_token_generate
    token = Rex::Text.rand_text_alphanumeric(32)
    db = false
    begin
      if framework.db and framework.db.active
        t = ::Mdm::ApiKey.new
        t.token = token
        t.save!
        db = true
      end
    rescue ::Exception
    end

    if not db
      token = "TEMP" + Rex::Text.rand_text_numeric(28)
      self.service.tokens[token] = [nil, nil, nil, true]
    end

    { "result" => "success", "token" => token }
  end


  # Removes a token from the database. Similar to what #rpc_logout does internally, except this
  # can remove tokens stored in the database backend (Mdm).
  #
  # @see #rpc_logout
  # @param [String] token The token to delete.
  # @return [Hash] A hash indicating the action was successful. It contains the following key:
  #  * 'result' [String] The successful message: 'success'
  # @example Here's how you would use this from the client:
  #  rpc.call('auth.token_remove', 'TEMPtcVmMld8w74zo0CYeosM3iXW0nJz')
  def rpc_token_remove(token)
    db = false
    begin
      if framework.db and framework.db.active
        t = ::Mdm::ApiKey.find_by_token(token)
        t.destroy if t
        db = true
      end
    rescue ::Exception
    end

    self.service.tokens.delete(token)

    { "result" => "success" }
  end

private

  def db_validate_auth(user,pass)
    return true if not (framework.db and framework.db.active)
    return true if not @@loaded_sha2

    user_info = ::Mdm::User.find_by_username(user)
    return true if not user_info

    # These settings match the CryptoProvider we use in AuthLogic
    jtoken    = ''
    stretches = 20
    algorithm = ::Digest::SHA512
    digest    = [pass,user_info.password_salt].compact.join(jtoken)
    stretches.times { digest = algorithm.hexdigest(digest) }
    # Flip true/false as the return value indicates failure
    ( user_info.crypted_password == digest ) ? false : true
  end

end
end
end

