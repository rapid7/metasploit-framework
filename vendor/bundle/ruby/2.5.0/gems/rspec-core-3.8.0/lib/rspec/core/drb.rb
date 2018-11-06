require 'drb/drb'

module RSpec
  module Core
    # @private
    class DRbRunner
      def initialize(options, configuration=RSpec.configuration)
        @options       = options
        @configuration = configuration
      end

      def drb_port
        @options.options[:drb_port] || ENV['RSPEC_DRB'] || 8989
      end

      def run(err, out)
        begin
          DRb.start_service("druby://localhost:0")
        rescue SocketError, Errno::EADDRNOTAVAIL
          DRb.start_service("druby://:0")
        end
        spec_server = DRbObject.new_with_uri("druby://127.0.0.1:#{drb_port}")
        spec_server.run(drb_argv, err, out)
      end

      def drb_argv
        @drb_argv ||= begin
          @options.configure_filter_manager(@configuration.filter_manager)
          DRbOptions.new(@options.options, @configuration.filter_manager).options
        end
      end
    end

    # @private
    class DRbOptions
      def initialize(submitted_options, filter_manager)
        @submitted_options = submitted_options
        @filter_manager = filter_manager
      end

      def options
        argv = []
        argv << "--color"        if @submitted_options[:color]
        argv << "--force-color"  if @submitted_options[:color_mode] == :on
        argv << "--no-color"     if @submitted_options[:color_mode] == :off
        argv << "--profile"      if @submitted_options[:profile_examples]
        argv << "--backtrace"    if @submitted_options[:full_backtrace]
        argv << "--tty"          if @submitted_options[:tty]
        argv << "--fail-fast"    if @submitted_options[:fail_fast]
        argv << "--options"      << @submitted_options[:custom_options_file] if @submitted_options[:custom_options_file]
        argv << "--order"        << @submitted_options[:order]               if @submitted_options[:order]

        add_failure_exit_code(argv)
        add_full_description(argv)
        add_filter(argv, :inclusion, @filter_manager.inclusions)
        add_filter(argv, :exclusion, @filter_manager.exclusions)
        add_formatters(argv)
        add_libs(argv)
        add_requires(argv)

        argv + @submitted_options[:files_or_directories_to_run]
      end

      def add_failure_exit_code(argv)
        return unless @submitted_options[:failure_exit_code]

        argv << "--failure-exit-code" << @submitted_options[:failure_exit_code].to_s
      end

      def add_full_description(argv)
        return unless @submitted_options[:full_description]

        # The argument to --example is regexp-escaped before being stuffed
        # into a regexp when received for the first time (see OptionParser).
        # Hence, merely grabbing the source of this regexp will retain the
        # backslashes, so we must remove them.
        @submitted_options[:full_description].each do |description|
          argv << "--example" << description.source.delete('\\')
        end
      end

      CONDITIONAL_FILTERS = [:if, :unless]

      def add_filter(argv, name, hash)
        hash.each_pair do |k, v|
          next if CONDITIONAL_FILTERS.include?(k)
          tag = name == :inclusion ? k.to_s : "~#{k}".dup
          tag << ":#{v}" if v.is_a?(String)
          argv << "--tag" << tag
        end unless hash.empty?
      end

      def add_formatters(argv)
        @submitted_options[:formatters].each do |pair|
          argv << "--format" << pair[0]
          argv << "--out" << pair[1] if pair[1]
        end if @submitted_options[:formatters]
      end

      def add_libs(argv)
        @submitted_options[:libs].each do |path|
          argv << "-I" << path
        end if @submitted_options[:libs]
      end

      def add_requires(argv)
        @submitted_options[:requires].each do |path|
          argv << "--require" << path
        end if @submitted_options[:requires]
      end
    end
  end
end
