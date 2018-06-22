module Authentication
  module Strategies
    autoload :ApiToken, 'msf/core/db_manager/http/authentication/strategies/api_token'
    autoload :UserPassword, 'msf/core/db_manager/http/authentication/strategies/user_password'

    include ApiToken
    include UserPassword
  end
end