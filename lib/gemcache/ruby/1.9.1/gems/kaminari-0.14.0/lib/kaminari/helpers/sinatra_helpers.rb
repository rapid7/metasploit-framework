require 'active_support/core_ext/object'
require 'active_support/core_ext/string'

begin

require 'padrino-helpers'
module Kaminari::Helpers
  module SinatraHelpers
    class << self
      def registered(app)
        app.register Padrino::Helpers
        app.helpers  HelperMethods
      end

      alias included registered
    end

    class ActionViewTemplateProxy
      include Padrino::Helpers::OutputHelpers
      include Padrino::Helpers::TagHelpers
      include Padrino::Helpers::AssetTagHelpers
      include Padrino::Helpers::FormatHelpers
      include Padrino::Helpers::TranslationHelpers

      def initialize(opts={})
        @current_path = opts[:current_path]
        @param_name = (opts[:param_name] || :page).to_sym
        @current_params = opts[:current_params]
        @current_params.delete(@param_name)
      end

      def render(*args)
        base = ActionView::Base.new.tap do |a|
          a.view_paths << File.expand_path('../../../../app/views', __FILE__)
        end
        base.render(*args)
      end

      def url_for(params)
        extra_params = {}
        if page = params[@param_name] and page != 1
          extra_params[@param_name] = page
        end
        query = @current_params.merge(extra_params)
        @current_path + (query.empty? ? '' : "?#{query.to_query}")
      end

      def link_to_unless(condition, name, options = {}, html_options = {}, &block)
        options = url_for(options) if options.is_a? Hash
        if condition
          if block_given?
            block.arity <= 1 ? capture(name, &block) : capture(name, options, html_options, &block)
          else
            name
          end
        else
          link_to(name, options, html_options)
        end
      end

      def params
        @current_params
      end
    end

    module HelperMethods
      # A helper that renders the pagination links - for Sinatra.
      #
      #   <%= paginate @articles %>
      #
      # ==== Options
      # * <tt>:window</tt> - The "inner window" size (4 by default).
      # * <tt>:outer_window</tt> - The "outer window" size (0 by default).
      # * <tt>:left</tt> - The "left outer window" size (0 by default).
      # * <tt>:right</tt> - The "right outer window" size (0 by default).
      # * <tt>:params</tt> - url_for parameters for the links (:id, :locale, etc.)
      # * <tt>:param_name</tt> - parameter name for page number in the links (:page by default)
      # * <tt>:remote</tt> - Ajax? (false by default)
      # * <tt>:ANY_OTHER_VALUES</tt> - Any other hash key & values would be directly passed into each tag as :locals value.
      def paginate(scope, options = {}, &block)
        current_path = env['PATH_INFO'] rescue nil
        current_params = Rack::Utils.parse_query(env['QUERY_STRING']).symbolize_keys rescue {}
        paginator = Kaminari::Helpers::Paginator.new(
          ActionViewTemplateProxy.new(:current_params => current_params, :current_path => current_path, :param_name => options[:param_name] || Kaminari.config.param_name),
          options.reverse_merge(:current_page => scope.current_page, :total_pages => scope.total_pages, :per_page => scope.limit_value, :param_name => Kaminari.config.param_name, :remote => false)
        )
        paginator.to_s
      end

      # A simple "Twitter like" pagination link that creates a link to the next page.
      # Works on Sinatra.
      #
      # ==== Examples
      # Basic usage:
      #
      #   <%= link_to_next_page @items, 'Next Page' %>
      #
      # Ajax:
      #
      #   <%= link_to_next_page @items, 'Next Page', :remote => true %>
      #
      # By default, it renders nothing if there are no more results on the next page.
      # You can customize this output by passing a parameter <tt>:placeholder</tt>.
      #
      #   <%= link_to_next_page @items, 'Next Page', :placeholder => %{<span>No More Pages</span>} %>
      #
      def link_to_next_page(scope, name, options = {})
        params = options.delete(:params) || (Rack::Utils.parse_query(env['QUERY_STRING']).symbolize_keys rescue {})
        param_name = options.delete(:param_name) || Kaminari.config.param_name
        placeholder = options.delete(:placeholder)
        query = params.merge(param_name => (scope.current_page + 1))
        unless scope.last_page?
          link_to name, env['PATH_INFO'] + (query.empty? ? '' : "?#{query.to_query}"), options.reverse_merge(:rel => 'next')
        else
          placeholder
        end
      end
    end
  end
end

if defined? I18n
  I18n.load_path += Dir.glob(File.expand_path('../../../../config/locales/*.yml', __FILE__))
end

rescue LoadError

$stderr.puts "[!]You shold install `padrino-helpers' gem if you want to use kaminari's pagination helpers with Sinatra."
$stderr.puts "[!]Kaminari::Helpers::SinatraHelper does nothing now..."

module Kaminari::Helpers
  module SinatraHelper
    def self.registered(*)
    end
  end
end

end
