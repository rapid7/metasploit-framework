RSpec::Support.require_rspec_support "directory_maker"
# ## Built-in Formatters
#
# * progress (default) - Prints dots for passing examples, `F` for failures, `*`
#                        for pending.
# * documentation - Prints the docstrings passed to `describe` and `it` methods
#                   (and their aliases).
# * html
# * json - Useful for archiving data for subsequent analysis.
#
# The progress formatter is the default, but you can choose any one or more of
# the other formatters by passing with the `--format` (or `-f` for short)
# command-line option, e.g.
#
#     rspec --format documentation
#
# You can also send the output of multiple formatters to different streams, e.g.
#
#     rspec --format documentation --format html --out results.html
#
# This example sends the output of the documentation formatter to `$stdout`, and
# the output of the html formatter to results.html.
#
# ## Custom Formatters
#
# You can tell RSpec to use a custom formatter by passing its path and name to
# the `rspec` command. For example, if you define MyCustomFormatter in
# path/to/my_custom_formatter.rb, you would type this command:
#
#     rspec --require path/to/my_custom_formatter.rb --format MyCustomFormatter
#
# The reporter calls every formatter with this protocol:
#
# * To start
#   * `start(StartNotification)`
# * Once per example group
#   * `example_group_started(GroupNotification)`
# * Once per example
#   * `example_started(ExampleNotification)`
# * One of these per example, depending on outcome
#   * `example_passed(ExampleNotification)`
#   * `example_failed(FailedExampleNotification)`
#   * `example_pending(ExampleNotification)`
# * Optionally at any time
#   * `message(MessageNotification)`
# * At the end of the suite
#   * `stop(ExamplesNotification)`
#   * `start_dump(NullNotification)`
#   * `dump_pending(ExamplesNotification)`
#   * `dump_failures(ExamplesNotification)`
#   * `dump_summary(SummaryNotification)`
#   * `seed(SeedNotification)`
#   * `close(NullNotification)`
#
# Only the notifications to which you subscribe your formatter will be called
# on your formatter. To subscribe your formatter use:
# `RSpec::Core::Formatters#register` e.g.
#
# `RSpec::Core::Formatters.register FormatterClassName, :example_passed, :example_failed`
#
# We recommend you implement the methods yourself; for simplicity we provide the
# default formatter output via our notification objects but if you prefer you
# can subclass `RSpec::Core::Formatters::BaseTextFormatter` and override the
# methods you wish to enhance.
#
# @see RSpec::Core::Formatters::BaseTextFormatter
# @see RSpec::Core::Reporter
module RSpec::Core::Formatters
  autoload :DocumentationFormatter,   'rspec/core/formatters/documentation_formatter'
  autoload :HtmlFormatter,            'rspec/core/formatters/html_formatter'
  autoload :FallbackMessageFormatter, 'rspec/core/formatters/fallback_message_formatter'
  autoload :ProgressFormatter,        'rspec/core/formatters/progress_formatter'
  autoload :ProfileFormatter,         'rspec/core/formatters/profile_formatter'
  autoload :JsonFormatter,            'rspec/core/formatters/json_formatter'
  autoload :BisectDRbFormatter,       'rspec/core/formatters/bisect_drb_formatter'
  autoload :ExceptionPresenter,       'rspec/core/formatters/exception_presenter'

  # Register the formatter class
  # @param formatter_class [Class] formatter class to register
  # @param notifications [Symbol, ...] one or more notifications to be
  #   registered to the specified formatter
  #
  # @see RSpec::Core::Formatters::BaseFormatter
  def self.register(formatter_class, *notifications)
    Loader.formatters[formatter_class] = notifications
  end

  # @api private
  #
  # `RSpec::Core::Formatters::Loader` is an internal class for
  # managing formatters used by a particular configuration. It is
  # not expected to be used directly, but only through the configuration
  # interface.
  class Loader
    # @api private
    #
    # Internal formatters are stored here when loaded.
    def self.formatters
      @formatters ||= {}
    end

    # @api private
    def initialize(reporter)
      @formatters = []
      @reporter = reporter
      self.default_formatter = 'progress'
    end

    # @return [Array] the loaded formatters
    attr_reader :formatters

    # @return [Reporter] the reporter
    attr_reader :reporter

    # @return [String] the default formatter to setup, defaults to `progress`
    attr_accessor :default_formatter

    # @private
    def prepare_default(output_stream, deprecation_stream)
      reporter.prepare_default(self, output_stream, deprecation_stream)
    end

    # @private
    def setup_default(output_stream, deprecation_stream)
      add default_formatter, output_stream if @formatters.empty?

      unless @formatters.any? { |formatter| DeprecationFormatter === formatter }
        add DeprecationFormatter, deprecation_stream, output_stream
      end

      unless existing_formatter_implements?(:message)
        add FallbackMessageFormatter, output_stream
      end

      return unless RSpec.configuration.profile_examples?
      return if existing_formatter_implements?(:dump_profile)

      add RSpec::Core::Formatters::ProfileFormatter, output_stream
    end

    # @private
    def add(formatter_to_use, *paths)
      # If a formatter instance was passed, we can register it directly,
      # with no need for any of the further processing that happens below.
      if Loader.formatters.key?(formatter_to_use.class)
        register formatter_to_use, notifications_for(formatter_to_use.class)
        return
      end

      formatter_class = find_formatter(formatter_to_use)

      args = paths.map { |p| p.respond_to?(:puts) ? p : open_stream(p) }

      if !Loader.formatters[formatter_class].nil?
        formatter = formatter_class.new(*args)
        register formatter, notifications_for(formatter_class)
      elsif defined?(RSpec::LegacyFormatters)
        formatter = RSpec::LegacyFormatters.load_formatter formatter_class, *args
        register formatter, formatter.notifications
      else
        call_site = "Formatter added at: #{::RSpec::CallerFilter.first_non_rspec_line}"

        RSpec.warn_deprecation <<-WARNING.gsub(/\s*\|/, ' ')
          |The #{formatter_class} formatter uses the deprecated formatter
          |interface not supported directly by RSpec 3.
          |
          |To continue to use this formatter you must install the
          |`rspec-legacy_formatters` gem, which provides support
          |for legacy formatters or upgrade the formatter to a
          |compatible version.
          |
          |#{call_site}
        WARNING
      end
    end

  private

    def find_formatter(formatter_to_use)
      built_in_formatter(formatter_to_use) ||
      custom_formatter(formatter_to_use)   ||
      (raise ArgumentError, "Formatter '#{formatter_to_use}' unknown - " \
                            "maybe you meant 'documentation' or 'progress'?.")
    end

    def register(formatter, notifications)
      return if duplicate_formatter_exists?(formatter)
      @reporter.register_listener formatter, *notifications
      @formatters << formatter
      formatter
    end

    def duplicate_formatter_exists?(new_formatter)
      @formatters.any? do |formatter|
        formatter.class == new_formatter.class && formatter.output == new_formatter.output
      end
    end

    def existing_formatter_implements?(notification)
      @reporter.registered_listeners(notification).any?
    end

    def built_in_formatter(key)
      case key.to_s
      when 'd', 'doc', 'documentation'
        DocumentationFormatter
      when 'h', 'html'
        HtmlFormatter
      when 'p', 'progress'
        ProgressFormatter
      when 'j', 'json'
        JsonFormatter
      when 'bisect-drb'
        BisectDRbFormatter
      end
    end

    def notifications_for(formatter_class)
      formatter_class.ancestors.inject(::RSpec::Core::Set.new) do |notifications, klass|
        notifications.merge Loader.formatters.fetch(klass) { ::RSpec::Core::Set.new }
      end
    end

    def custom_formatter(formatter_ref)
      if Class === formatter_ref
        formatter_ref
      elsif string_const?(formatter_ref)
        begin
          formatter_ref.gsub(/^::/, '').split('::').inject(Object) { |a, e| a.const_get e }
        rescue NameError
          require(path_for(formatter_ref)) ? retry : raise
        end
      end
    end

    def string_const?(str)
      str.is_a?(String) && /\A[A-Z][a-zA-Z0-9_:]*\z/ =~ str
    end

    def path_for(const_ref)
      underscore_with_fix_for_non_standard_rspec_naming(const_ref)
    end

    def underscore_with_fix_for_non_standard_rspec_naming(string)
      underscore(string).sub(%r{(^|/)r_spec($|/)}, '\\1rspec\\2')
    end

    # activesupport/lib/active_support/inflector/methods.rb, line 48
    def underscore(camel_cased_word)
      word = camel_cased_word.to_s.dup
      word.gsub!(/::/, '/')
      word.gsub!(/([A-Z]+)([A-Z][a-z])/, '\1_\2')
      word.gsub!(/([a-z\d])([A-Z])/, '\1_\2')
      word.tr!("-", "_")
      word.downcase!
      word
    end

    def open_stream(path_or_wrapper)
      if RSpec::Core::OutputWrapper === path_or_wrapper
        path_or_wrapper.output = open_stream(path_or_wrapper.output)
        path_or_wrapper
      else
        RSpec::Support::DirectoryMaker.mkdir_p(File.dirname(path_or_wrapper))
        File.new(path_or_wrapper, 'w')
      end
    end
  end
end
