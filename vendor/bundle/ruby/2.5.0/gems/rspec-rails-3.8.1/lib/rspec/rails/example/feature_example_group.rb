module RSpec
  module Rails
    # @api public
    # Container module for routing spec functionality.
    module FeatureExampleGroup
      extend ActiveSupport::Concern
      include RSpec::Rails::RailsExampleGroup

      # Default host to be used in Rails route helpers if none is specified.
      DEFAULT_HOST = "www.example.com"

      included do
        app = ::Rails.application
        if app.respond_to?(:routes)
          include app.routes.url_helpers     if app.routes.respond_to?(:url_helpers)
          include app.routes.mounted_helpers if app.routes.respond_to?(:mounted_helpers)

          if respond_to?(:default_url_options)
            default_url_options[:host] ||= ::RSpec::Rails::FeatureExampleGroup::DEFAULT_HOST
          end
        end
      end

      # Shim to check for presence of Capybara. Will delegate if present, raise
      # if not. We assume here that in most cases `visit` will be the first
      # Capybara method called in a spec.
      def visit(*)
        if defined?(super)
          super
        else
          raise "Capybara not loaded, please add it to your Gemfile:\n\ngem \"capybara\""
        end
      end
    end
  end
end

unless RSpec.respond_to?(:feature)
  opts = {
    :capybara_feature => true,
    :type => :feature,
    :skip => <<-EOT.squish
      Feature specs require the Capybara (http://github.com/jnicklas/capybara)
      gem, version 2.2.0 or later. We recommend version 2.4.0 or later to avoid
      some deprecation warnings and have support for
      `config.expose_dsl_globally = false`.
    EOT
  }

  # Capybara's monkey patching causes us to have to jump through some hoops
  top_level = self
  main_feature = nil
  if defined?(Capybara) && ::Capybara::VERSION.to_f < 2.4
    # Capybara 2.2 and 2.3 do not use `alias_example_xyz`
    opts[:skip] = <<-EOT.squish
      Capybara < 2.4.0 does not support RSpec's namespace or
      `config.expose_dsl_globally = false`. Upgrade to Capybara >= 2.4.0.
    EOT
    main_feature = top_level.method(:feature) if top_level.respond_to?(:feature)
  end

  RSpec.configure do |c|
    main_feature = nil unless c.expose_dsl_globally?
    c.alias_example_group_to :feature, opts
    c.alias_example_to :scenario
    c.alias_example_to :xscenario, :skip => 'Temporarily skipped with xscenario'
  end

  # Due to load order issues and `config.expose_dsl_globally?` defaulting to
  # `true` we need to put Capybara's monkey patch method back. Otherwise,
  # app upgrades have a high likelyhood of having all feature specs skipped.
  top_level.define_singleton_method(:feature, &main_feature) if main_feature
end
