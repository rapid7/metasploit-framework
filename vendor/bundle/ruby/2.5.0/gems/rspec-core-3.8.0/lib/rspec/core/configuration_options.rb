require 'erb'
require 'shellwords'

module RSpec
  module Core
    # Responsible for utilizing externally provided configuration options,
    # whether via the command line, `.rspec`, `~/.rspec`,
    # `$XDG_CONFIG_HOME/rspec/options`, `.rspec-local` or a custom options
    # file.
    class ConfigurationOptions
      # @param args [Array<String>] command line arguments
      def initialize(args)
        @args = args.dup
        organize_options
      end

      # Updates the provided {Configuration} instance based on the provided
      # external configuration options.
      #
      # @param config [Configuration] the configuration instance to update
      def configure(config)
        process_options_into config
        configure_filter_manager config.filter_manager
        load_formatters_into config
      end

      # @api private
      # Updates the provided {FilterManager} based on the filter options.
      # @param filter_manager [FilterManager] instance to update
      def configure_filter_manager(filter_manager)
        @filter_manager_options.each do |command, value|
          filter_manager.__send__ command, value
        end
      end

      # @return [Hash] the final merged options, drawn from all external sources
      attr_reader :options

      # @return [Array<String>] the original command-line arguments
      attr_reader :args

    private

      def organize_options
        @filter_manager_options = []

        @options = (file_options << command_line_options << env_options).each do |opts|
          @filter_manager_options << [:include, opts.delete(:inclusion_filter)] if opts.key?(:inclusion_filter)
          @filter_manager_options << [:exclude, opts.delete(:exclusion_filter)] if opts.key?(:exclusion_filter)
        end

        @options = @options.inject(:libs => [], :requires => []) do |hash, opts|
          hash.merge(opts) do |key, oldval, newval|
            [:libs, :requires].include?(key) ? oldval + newval : newval
          end
        end
      end

      UNFORCED_OPTIONS = Set.new([
        :requires, :profile, :drb, :libs, :files_or_directories_to_run,
        :full_description, :full_backtrace, :tty
      ])

      UNPROCESSABLE_OPTIONS = Set.new([:formatters])

      def force?(key)
        !UNFORCED_OPTIONS.include?(key)
      end

      def order(keys)
        OPTIONS_ORDER.reverse_each do |key|
          keys.unshift(key) if keys.delete(key)
        end
        keys
      end

      OPTIONS_ORDER = [
        # It's important to set this before anything that might issue a
        # deprecation (or otherwise access the reporter).
        :deprecation_stream,

        # load paths depend on nothing, but must be set before `requires`
        # to support load-path-relative requires.
        :libs,

        # `files_or_directories_to_run` uses `default_path` so it must be
        # set before it.
        :default_path, :only_failures,

        # These must be set before `requires` to support checking
        # `config.files_to_run` from within `spec_helper.rb` when a
        # `-rspec_helper` option is used.
        :files_or_directories_to_run, :pattern, :exclude_pattern,

        # Necessary so that the `--seed` option is applied before requires,
        # in case required files do something with the provided seed.
        # (such as seed global randomization with it).
        :order,

        # In general, we want to require the specified files as early as
        # possible. The `--require` option is specifically intended to allow
        # early requires. For later requires, they can just put the require in
        # their spec files, but `--require` provides a unique opportunity for
        # users to instruct RSpec to load an extension file early for maximum
        # flexibility.
        :requires
      ]

      def process_options_into(config)
        opts = options.reject { |k, _| UNPROCESSABLE_OPTIONS.include? k }

        order(opts.keys).each do |key|
          force?(key) ? config.force(key => opts[key]) : config.__send__("#{key}=", opts[key])
        end
      end

      def load_formatters_into(config)
        options[:formatters].each { |pair| config.add_formatter(*pair) } if options[:formatters]
      end

      def file_options
        if custom_options_file
          [custom_options]
        else
          [global_options, project_options, local_options]
        end
      end

      def env_options
        return {} unless ENV['SPEC_OPTS']

        parse_args_ignoring_files_or_dirs_to_run(
          Shellwords.split(ENV["SPEC_OPTS"]),
          "ENV['SPEC_OPTS']"
        )
      end

      def command_line_options
        @command_line_options ||= Parser.parse(@args)
      end

      def custom_options
        options_from(custom_options_file)
      end

      def local_options
        @local_options ||= options_from(local_options_file)
      end

      def project_options
        @project_options ||= options_from(project_options_file)
      end

      def global_options
        @global_options ||= options_from(global_options_file)
      end

      def options_from(path)
        args = args_from_options_file(path)
        parse_args_ignoring_files_or_dirs_to_run(args, path)
      end

      def parse_args_ignoring_files_or_dirs_to_run(args, source)
        options = Parser.parse(args, source)
        options.delete(:files_or_directories_to_run)
        options
      end

      def args_from_options_file(path)
        return [] unless path && File.exist?(path)
        config_string = options_file_as_erb_string(path)
        FlatMap.flat_map(config_string.split(/\n+/), &:shellsplit)
      end

      def options_file_as_erb_string(path)
        if RUBY_VERSION >= '2.6'
          ERB.new(File.read(path), :trim_mode => '-').result(binding)
        else
          ERB.new(File.read(path), nil, '-').result(binding)
        end
      end

      def custom_options_file
        command_line_options[:custom_options_file]
      end

      def project_options_file
        "./.rspec"
      end

      def local_options_file
        "./.rspec-local"
      end

      def global_options_file
        xdg_options_file_if_exists || home_options_file_path
      end

      def xdg_options_file_if_exists
        path = xdg_options_file_path
        if path && File.exist?(path)
          path
        end
      end

      def home_options_file_path
        File.join(File.expand_path("~"), ".rspec")
      rescue ArgumentError
        # :nocov:
        RSpec.warning "Unable to find ~/.rspec because the HOME environment variable is not set"
        nil
        # :nocov:
      end

      def xdg_options_file_path
        xdg_config_home = resolve_xdg_config_home
        if xdg_config_home
          File.join(xdg_config_home, "rspec", "options")
        end
      end

      def resolve_xdg_config_home
        File.expand_path(ENV.fetch("XDG_CONFIG_HOME", "~/.config"))
      rescue ArgumentError
        # :nocov:
        # On Ruby 2.4, `File.expand("~")` works even if `ENV['HOME']` is not set.
        # But on earlier versions, it fails.
        nil
        # :nocov:
      end
    end
  end
end
