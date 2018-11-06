require 'rspec/rails/view_assigns'
require 'rspec/rails/view_spec_methods'
require 'rspec/rails/view_path_builder'

module RSpec
  module Rails
    # @api public
    # Container class for view spec functionality.
    module ViewExampleGroup
      extend ActiveSupport::Concern
      include RSpec::Rails::RailsExampleGroup
      include ActionView::TestCase::Behavior
      include RSpec::Rails::ViewAssigns
      include RSpec::Rails::Matchers::RenderTemplate

      # @private
      module StubResolverCache
        def self.resolver_for(hash)
          @resolvers ||= {}
          @resolvers[hash] ||= ActionView::FixtureResolver.new(hash)
        end
      end

      # @private
      module ClassMethods
        def _default_helper
          base = metadata[:description].split('/')[0..-2].join('/')
          (base.camelize + 'Helper').constantize unless base.to_s.empty?
        rescue NameError
          nil
        end

        def _default_helpers
          helpers = [_default_helper].compact
          helpers << ApplicationHelper if Object.const_defined?('ApplicationHelper')
          helpers
        end
      end

      # DSL exposed to view specs.
      module ExampleMethods
        extend ActiveSupport::Concern

        included do
          include ::Rails.application.routes.url_helpers

          if ::Rails.application.routes.respond_to?(:mounted_helpers)
            include ::Rails.application.routes.mounted_helpers
          end
        end

        # @overload render
        # @overload render({:partial => path_to_file})
        # @overload render({:partial => path_to_file}, {... locals ...})
        # @overload render({:partial => path_to_file}, {... locals ...}) do ... end
        #
        # Delegates to ActionView::Base#render, so see documentation on that
        # for more info.
        #
        # The only addition is that you can call render with no arguments, and
        # RSpec will pass the top level description to render:
        #
        #     describe "widgets/new.html.erb" do
        #       it "shows all the widgets" do
        #         render # => view.render(:file => "widgets/new.html.erb")
        #         # ...
        #       end
        #     end
        def render(options = {}, local_assigns = {}, &block)
          options = _default_render_options if Hash === options && options.empty?
          super(options, local_assigns, &block)
        end

        # The instance of `ActionView::Base` that is used to render the template.
        # Use this to stub methods _before_ calling `render`.
        #
        #     describe "widgets/new.html.erb" do
        #       it "shows all the widgets" do
        #         view.stub(:foo) { "foo" }
        #         render
        #         # ...
        #       end
        #     end
        def view
          _view
        end

        # Simulates the presence of a template on the file system by adding a
        # Rails' FixtureResolver to the front of the view_paths list. Designed to
        # help isolate view examples from partials rendered by the view template
        # that is the subject of the example.
        #
        #     stub_template("widgets/_widget.html.erb" => "This content.")
        def stub_template(hash)
          view.view_paths.unshift(StubResolverCache.resolver_for(hash))
        end

        # Provides access to the params hash that will be available within the
        # view.
        #
        #     params[:foo] = 'bar'
        def params
          controller.params
        end

        # @deprecated Use `view` instead.
        def template
          RSpec.deprecate("template", :replacement => "view")
          view
        end

        # @deprecated Use `rendered` instead.
        def response
          # `assert_template` expects `response` to implement a #body method
          # like an `ActionDispatch::Response` does to force the view to
          # render. For backwards compatibility, we use #response as an alias
          # for #rendered, but it needs to implement #body to avoid
          # `assert_template` raising a `NoMethodError`.
          unless rendered.respond_to?(:body)
            def rendered.body
              self
            end
          end

          rendered
        end

      private

        def _default_render_options
          if ::Rails::VERSION::STRING >= '3.2'
            # pluck the handler, format, and locale out of, eg, posts/index.de.html.haml
            template, *components   = _default_file_to_render.split('.')
            handler, format, locale = *components.reverse

            render_options = { :template => template }
            render_options[:handlers] = [handler] if handler
            render_options[:formats] = [format.to_sym] if format
            render_options[:locales] = [locale] if locale

            render_options
          else
            { :template => _default_file_to_render }
          end
        end

        def _path_parts
          _default_file_to_render.split("/")
        end

        def _controller_path
          _path_parts[0..-2].join("/")
        end

        def _inferred_action
          _path_parts.last.split(".").first
        end

        def _include_controller_helpers
          helpers = controller._helpers
          view.singleton_class.class_exec do
            include helpers unless included_modules.include?(helpers)
          end
        end
      end

      included do
        include ExampleMethods

        helper(*_default_helpers)

        before do
          _include_controller_helpers
          if view.lookup_context.respond_to?(:prefixes)
            # rails 3.1
            view.lookup_context.prefixes << _controller_path
          end

          controller.controller_path = _controller_path

          path_params_to_merge = {}
          path_params_to_merge[:controller] = _controller_path
          path_params_to_merge[:action] = _inferred_action unless _inferred_action =~ /^_/

          path_params = controller.request.path_parameters

          controller.request.path_parameters = path_params.reverse_merge(path_params_to_merge)
          controller.request.path = ViewPathBuilder.new(::Rails.application.routes).path_for(controller.request.path_parameters)
          ViewSpecMethods.add_to(::ActionView::TestCase::TestController)
        end

        after do
          ViewSpecMethods.remove_from(::ActionView::TestCase::TestController)
        end

        let(:_default_file_to_render) do |example|
          example.example_group.top_level_description
        end
      end
    end
  end
end
