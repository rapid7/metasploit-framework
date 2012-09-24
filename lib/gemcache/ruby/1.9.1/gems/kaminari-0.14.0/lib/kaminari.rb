module Kaminari
end

# load Rails/Railtie
begin
  require 'rails'
rescue LoadError
  #do nothing
end

$stderr.puts <<-EOC if !defined?(Rails) && !defined?(Sinatra) && !defined?(Grape)
warning: no framework detected.
would you check out if your Gemfile appropriately configured?
---- e.g. ----
when Rails:
    gem 'kaminari'

when Sinatra/Padrino:
    gem 'kaminari', :require => 'kaminari/sinatra'

when Grape:
    gem 'kaminari', :require => 'kaminari/grape'

EOC

# load Kaminari components
require 'kaminari/config'
require 'kaminari/helpers/action_view_extension'
require 'kaminari/helpers/paginator'
require 'kaminari/models/page_scope_methods'
require 'kaminari/models/configuration_methods'
require 'kaminari/hooks'

# if not using Railtie, call `Kaminari::Hooks.init` directly
if defined? Rails
  require 'kaminari/railtie'
  require 'kaminari/engine'
end
