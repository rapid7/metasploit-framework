module Kaminari
  class Railtie < ::Rails::Railtie #:nodoc:
    initializer 'kaminari' do |_app|
      Kaminari::Hooks.init
    end
  end
end
