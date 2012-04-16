require 'journey/core-ext/hash'
require 'journey/router/utils'
require 'journey/router/strexp'
require 'journey/routes'
require 'journey/formatter'

before = $-w
$-w = false
require 'journey/parser'
$-w = before

require 'journey/route'
require 'journey/path/pattern'

module Journey
  class Router
    class RoutingError < ::StandardError
    end

    VERSION = '1.0.3'

    class NullReq # :nodoc:
      attr_reader :env
      def initialize env
        @env = env
      end

      def request_method
        env['REQUEST_METHOD']
      end

      def path_info
        env['PATH_INFO']
      end

      def ip
        env['REMOTE_ADDR']
      end

      def [](k); env[k]; end
    end

    attr_reader :request_class, :formatter
    attr_accessor :routes

    def initialize routes, options
      @options       = options
      @params_key    = options[:parameters_key]
      @request_class = options[:request_class] || NullReq
      @routes        = routes
    end

    def call env
      env['PATH_INFO'] = Utils.normalize_path env['PATH_INFO']

      find_routes(env).each do |match, parameters, route|
        script_name, path_info, set_params = env.values_at('SCRIPT_NAME',
                                                           'PATH_INFO',
                                                           @params_key)

        unless route.path.anchored
          env['SCRIPT_NAME'] = script_name.to_s + match.to_s
          env['PATH_INFO']   = match.post_match
        end

        env[@params_key] = (set_params || {}).merge parameters

        status, headers, body = route.app.call(env)

        if 'pass' == headers['X-Cascade']
          env['SCRIPT_NAME'] = script_name
          env['PATH_INFO']   = path_info
          env[@params_key]   = set_params
          next
        end

        return [status, headers, body]
      end

      return [404, {'X-Cascade' => 'pass'}, ['Not Found']]
    end

    def recognize req
      find_routes(req.env).each do |match, parameters, route|
        unless route.path.anchored
          req.env['SCRIPT_NAME'] = match.to_s
          req.env['PATH_INFO']   = match.post_match.sub(/^([^\/])/, '/\1')
        end

        yield(route, nil, parameters)
      end
    end

    def visualizer
      tt     = GTG::Builder.new(ast).transition_table
      groups = partitioned_routes.first.map(&:ast).group_by { |a| a.to_s }
      asts   = groups.values.map { |v| v.first }
      tt.visualizer asts
    end

    private

    def partitioned_routes
      routes.partitioned_routes
    end

    def ast
      routes.ast
    end

    def simulator
      routes.simulator
    end

    def custom_routes
      partitioned_routes.last
    end

    def filter_routes path
      return [] unless ast
      data = simulator.match(path)
      data ? data.memos : []
    end

    def find_routes env
      req = request_class.new env

      routes = filter_routes(req.path_info) + custom_routes.find_all { |r|
        r.path.match(req.path_info)
      }

      routes.sort_by(&:precedence).find_all { |r|
        r.constraints.all? { |k,v| v === req.send(k) } &&
          r.verb === req.request_method
      }.reject { |r| req.ip && !(r.ip === req.ip) }.map { |r|
        match_data  = r.path.match(req.path_info)
        match_names = match_data.names.map { |n| n.to_sym }
        match_values = match_data.captures.map { |v| v && Utils.unescape_uri(v) }
        info = Hash[match_names.zip(match_values).find_all { |_,y| y }]

        [match_data, r.defaults.merge(info), r]
      }
    end
  end
end
