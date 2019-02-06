module Authentication
  autoload :Strategies, 'msf/core/web_services/authentication/strategies'

  include Strategies
end