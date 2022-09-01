require 'warden'

module Msf::WebServices::Authentication
  module Strategies
    Warden::Strategies.add(:api_token, Msf::WebServices::Authentication::Strategies::ApiToken)
    Warden::Strategies.add(:admin_api_token, Msf::WebServices::Authentication::Strategies::AdminApiToken)
    Warden::Strategies.add(:password, Msf::WebServices::Authentication::Strategies::UserPassword)
  end
end
