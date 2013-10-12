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
      Rex.sleep(delay)

      # Send back a 401 denied error
      error(401, "Login Failed")
    end

    token = "TEMP" + Rex::Text.rand_text_alphanumeric(28)
    self.service.tokens[token] = [user, Time.now.to_i, Time.now.to_i]
    { "result" => "success", "token" => token }
  end

  def rpc_logout(token)
    found = self.service.tokens[token]
    error("500", "Invalid Authentication Token") if not found
    error("500", "Permanent Authentication Token") if found[3] == true

    # Delete the token if its not marked as permanent
    self.service.tokens.delete(token)

    { "result" => "success" }
  end

  def rpc_token_list
    res = self.service.tokens.keys
    begin
      if framework.db and framework.db.active
        ::Mdm::ApiKey.find(:all).each do |k|
          res << k.token
        end
      end
    rescue ::Exception
    end
    { "tokens" => res }
  end

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

