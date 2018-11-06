module RSpec
  module Rails
    # @private
    ControllerAssertionDelegator = RSpec::Rails::AssertionDelegator.new(
      ActionDispatch::Assertions::RoutingAssertions
    )

    # @api public
    # Container module for controller spec functionality.
    module ControllerExampleGroup
      extend ActiveSupport::Concern
      include RSpec::Rails::RailsExampleGroup
      include ActionController::TestCase::Behavior
      include RSpec::Rails::ViewRendering
      include RSpec::Rails::Matchers::RedirectTo
      include RSpec::Rails::Matchers::RenderTemplate
      include RSpec::Rails::Matchers::RoutingMatchers
      include ControllerAssertionDelegator

      # Class-level DSL for controller specs.
      module ClassMethods
        # @private
        def controller_class
          described_class
        end

        # Supports a simple DSL for specifying behavior of ApplicationController.
        # Creates an anonymous subclass of ApplicationController and evals the
        # `body` in that context. Also sets up implicit routes for this
        # controller, that are separate from those defined in "config/routes.rb".
        #
        # @note Due to Ruby 1.8 scoping rules in anonymous subclasses, constants
        #   defined in `ApplicationController` must be fully qualified (e.g.
        #   `ApplicationController::AccessDenied`) in the block passed to the
        #   `controller` method. Any instance methods, filters, etc, that are
        #   defined in `ApplicationController`, however, are accessible from
        #   within the block.
        #
        # @example
        #     describe ApplicationController do
        #       controller do
        #         def index
        #           raise ApplicationController::AccessDenied
        #         end
        #       end
        #
        #       describe "handling AccessDenied exceptions" do
        #         it "redirects to the /401.html page" do
        #           get :index
        #           response.should redirect_to("/401.html")
        #         end
        #       end
        #     end
        #
        # If you would like to spec a subclass of ApplicationController, call
        # controller like so:
        #
        #     controller(ApplicationControllerSubclass) do
        #       # ....
        #     end
        def controller(base_class = nil, &body)
          if RSpec.configuration.infer_base_class_for_anonymous_controllers?
            base_class ||= controller_class
          end
          base_class ||= defined?(ApplicationController) ? ApplicationController : ActionController::Base

          new_controller_class = Class.new(base_class) do
            def self.name
              root_controller = defined?(ApplicationController) ? ApplicationController : ActionController::Base
              if superclass == root_controller || superclass.abstract?
                "AnonymousController"
              else
                superclass.name
              end
            end
          end
          new_controller_class.class_exec(&body)
          (class << self; self; end).__send__(:define_method, :controller_class) { new_controller_class }

          before do
            @orig_routes = routes
            resource_name = if @controller.respond_to?(:controller_name)
                              @controller.controller_name.to_sym
                            else
                              :anonymous
                            end
            resource_path = if @controller.respond_to?(:controller_path)
                              @controller.controller_path
                            else
                              resource_name.to_s
                            end
            resource_module = resource_path.rpartition('/').first.presence
            resource_as = 'anonymous_' + resource_path.tr('/', '_')
            self.routes = ActionDispatch::Routing::RouteSet.new.tap do |r|
              r.draw do
                resources resource_name,
                          :as => resource_as,
                          :module => resource_module,
                          :path => resource_path
              end
            end
          end

          after do
            self.routes  = @orig_routes
            @orig_routes = nil
          end
        end

        # Specifies the routeset that will be used for the example group. This
        # is most useful when testing Rails engines.
        #
        # @example
        #     describe MyEngine::PostsController do
        #       routes { MyEngine::Engine.routes }
        #
        #       # ...
        #     end
        def routes
          before do
            self.routes = yield
          end
        end
      end

      # @!attribute [r]
      # Returns the controller object instance under test.
      attr_reader :controller

      # @!attribute [r]
      # Returns the Rails routes used for the spec.
      attr_reader :routes

      # @private
      #
      # RSpec Rails uses this to make Rails routes easily available to specs.
      def routes=(routes)
        @routes = routes
        assertion_instance.instance_variable_set(:@routes, routes)
      end

      # @private
      module BypassRescue
        def rescue_with_handler(exception)
          raise exception
        end
      end

      # Extends the controller with a module that overrides
      # `rescue_with_handler` to raise the exception passed to it. Use this to
      # specify that an action _should_ raise an exception given appropriate
      # conditions.
      #
      # @example
      #     describe ProfilesController do
      #       it "raises a 403 when a non-admin user tries to view another user's profile" do
      #         profile = create_profile
      #         login_as profile.user
      #
      #         expect do
      #           bypass_rescue
      #           get :show, :id => profile.id + 1
      #         end.to raise_error(/403 Forbidden/)
      #       end
      #     end
      def bypass_rescue
        controller.extend(BypassRescue)
      end

      # If method is a named_route, delegates to the RouteSet associated with
      # this controller.
      def method_missing(method, *args, &block)
        if route_available?(method)
          controller.send(method, *args, &block)
        else
          super
        end
      end

      included do
        subject { controller }

        before do
          self.routes = ::Rails.application.routes
        end

        around do |ex|
          previous_allow_forgery_protection_value = ActionController::Base.allow_forgery_protection
          begin
            ActionController::Base.allow_forgery_protection = false
            ex.call
          ensure
            ActionController::Base.allow_forgery_protection = previous_allow_forgery_protection_value
          end
        end
      end

    private

      def route_available?(method)
        (defined?(@routes) && route_defined?(routes, method)) ||
          (defined?(@orig_routes) && route_defined?(@orig_routes, method))
      end

      def route_defined?(routes, method)
        return false if routes.nil?

        if routes.named_routes.respond_to?(:route_defined?)
          routes.named_routes.route_defined?(method)
        else
          routes.named_routes.helpers.include?(method)
        end
      end
    end
  end
end
