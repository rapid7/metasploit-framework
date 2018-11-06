module RSpec
  module Rails
    # Builds paths for view specs using a particular route set.
    class ViewPathBuilder
      def initialize(route_set)
        self.class.send(:include, route_set.url_helpers)
      end

      # Given a hash of parameters, build a view path, if possible.
      # Returns nil if no path can be built from the given params.
      #
      # @example
      #     # path can be built because all required params are present in the hash
      #     view_path_builder = ViewPathBuilder.new(::Rails.application.routes)
      #     view_path_builder.path_for({ :controller => 'posts', :action => 'show', :id => '54' })
      #     # => "/post/54"
      #
      # @example
      #     # path cannot be built because the params are missing a required element (:id)
      #     view_path_builder.path_for({ :controller => 'posts', :action => 'delete' })
      #     # => ActionController::UrlGenerationError: No route matches {:action=>"delete", :controller=>"posts"}
      def path_for(path_params)
        url_for(path_params.merge(:only_path => true))
      rescue => e
        e.message
      end
    end
  end
end
