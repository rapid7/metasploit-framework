module Authentication
  module Strategies
    autoload :ApiToken, 'msf/core/db_manager/http/authentication/strategies/api_token'
    autoload :AdminApiToken, 'msf/core/db_manager/http/authentication/strategies/admin_api_token'
    autoload :UserPassword, 'msf/core/db_manager/http/authentication/strategies/user_password'

    Warden::Strategies.add(:api_token, Authentication::Strategies::ApiToken)
    Warden::Strategies.add(:admin_api_token, Authentication::Strategies::AdminApiToken)
    Warden::Strategies.add(:password, Authentication::Strategies::UserPassword)
  end
end