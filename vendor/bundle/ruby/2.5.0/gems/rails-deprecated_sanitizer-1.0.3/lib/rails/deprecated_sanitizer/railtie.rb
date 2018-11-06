require 'rails/railtie'

module Rails
  module DeprecatedSanitizer
    class Railtie < Rails::Railtie
      config.eager_load_namespaces << HTML
    end
  end
end
