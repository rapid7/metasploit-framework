module Authentication
  autoload :Strategies, 'msf/core/db_manager/http/authentication/strategies'

  include Strategies
end