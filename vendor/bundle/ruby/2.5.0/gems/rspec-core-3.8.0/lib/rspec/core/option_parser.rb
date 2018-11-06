# http://www.ruby-doc.org/stdlib/libdoc/optparse/rdoc/classes/OptionParser.html
require 'optparse'

module RSpec::Core
  # @private
  class Parser
    def self.parse(args, source=nil)
      new(args).parse(source)
    end

    attr_reader :original_args

    def initialize(original_args)
      @original_args = original_args
    end

    def parse(source=nil)
      return { :files_or_directories_to_run => [] } if original_args.empty?
      args = original_args.dup

      options = args.delete('--tty') ? { :tty => true } : {}
      begin
        parser(options).parse!(args)
      rescue OptionParser::InvalidOption => e
        failure = e.message
        failure << " (defined in #{source})" if source
        abort "#{failure}\n\nPlease use --help for a listing of valid options"
      end

      options[:files_or_directories_to_run] = args
      options
    end

  private

    # rubocop:disable MethodLength
    # rubocop:disable Metrics/AbcSize
    # rubocop:disable CyclomaticComplexity
    # rubocop:disable PerceivedComplexity
    def parser(options)
      OptionParser.new do |parser|
        parser.summary_width = 34

        parser.banner = "Usage: rspec [options] [files or directories]\n\n"

        parser.on('-I PATH', 'Specify PATH to add to $LOAD_PATH (may be used more than once).') do |dirs|
          options[:libs] ||= []
          options[:libs].concat(dirs.split(File::PATH_SEPARATOR))
        end

        parser.on('-r', '--require PATH', 'Require a file.') do |path|
          options[:requires] ||= []
          options[:requires] << path
        end

        parser.on('-O', '--options PATH', 'Specify the path to a custom options file.') do |path|
          options[:custom_options_file] = path
        end

        parser.on('--order TYPE[:SEED]', 'Run examples by the specified order type.',
                  '  [defined] examples and groups are run in the order they are defined',
                  '  [rand]    randomize the order of groups and examples',
                  '  [random]  alias for rand',
                  '  [random:SEED] e.g. --order random:123') do |o|
          options[:order] = o
        end

        parser.on('--seed SEED', Integer, 'Equivalent of --order rand:SEED.') do |seed|
          options[:order] = "rand:#{seed}"
        end

        parser.on('--bisect[=verbose]', 'Repeatedly runs the suite in order to isolate the failures to the ',
                  '  smallest reproducible case.') do |argument|
          options[:bisect] = argument || true
          options[:runner] = RSpec::Core::Invocations::Bisect.new
        end

        parser.on('--[no-]fail-fast[=COUNT]', 'Abort the run after a certain number of failures (1 by default).') do |argument|
          if argument == true
            value = 1
          elsif argument == false || argument == 0
            value = false
          else
            begin
              value = Integer(argument)
            rescue ArgumentError
              RSpec.warning "Expected an integer value for `--fail-fast`, got: #{argument.inspect}", :call_site => nil
            end
          end
          set_fail_fast(options, value)
        end

        parser.on('--failure-exit-code CODE', Integer,
                  'Override the exit code used when there are failing specs.') do |code|
          options[:failure_exit_code] = code
        end

        parser.on('-X', '--[no-]drb', 'Run examples via DRb.') do |use_drb|
          options[:drb] = use_drb
          options[:runner] = RSpec::Core::Invocations::DRbWithFallback.new if use_drb
        end

        parser.on('--drb-port PORT', 'Port to connect to the DRb server.') do |o|
          options[:drb_port] = o.to_i
        end

        parser.separator("\n  **** Output ****\n\n")

        parser.on('-f', '--format FORMATTER', 'Choose a formatter.',
                  '  [p]rogress (default - dots)',
                  '  [d]ocumentation (group and example names)',
                  '  [h]tml',
                  '  [j]son',
                  '  custom formatter class name') do |o|
          options[:formatters] ||= []
          options[:formatters] << [o]
        end

        parser.on('-o', '--out FILE',
                  'Write output to a file instead of $stdout. This option applies',
                  '  to the previously specified --format, or the default format',
                  '  if no format is specified.'
                 ) do |o|
          options[:formatters] ||= [['progress']]
          options[:formatters].last << o
        end

        parser.on('--deprecation-out FILE', 'Write deprecation warnings to a file instead of $stderr.') do |file|
          options[:deprecation_stream] = file
        end

        parser.on('-b', '--backtrace', 'Enable full backtrace.') do |_o|
          options[:full_backtrace] = true
        end

        parser.on('-c', '--color', '--colour', '') do |_o|
          # flag will be excluded from `--help` output because it is deprecated
          options[:color] = true
          options[:color_mode] = :automatic
        end

        parser.on('--force-color', '--force-colour', 'Force the output to be in color, even if the output is not a TTY') do |_o|
          if options[:color_mode] == :off
            abort "Please only use one of `--force-color` and `--no-color`"
          end
          options[:color_mode] = :on
        end

        parser.on('--no-color', '--no-colour', 'Force the output to not be in color, even if the output is a TTY') do |_o|
          if options[:color_mode] == :on
            abort "Please only use one of --force-color and --no-color"
          end
          options[:color_mode] = :off
        end

        parser.on('-p', '--[no-]profile [COUNT]',
                  'Enable profiling of examples and list the slowest examples (default: 10).') do |argument|
          options[:profile_examples] = if argument.nil?
                                         true
                                       elsif argument == false
                                         false
                                       else
                                         begin
                                           Integer(argument)
                                         rescue ArgumentError
                                           RSpec.warning "Non integer specified as profile count, separate " \
                                                       "your path from options with -- e.g. " \
                                                       "`rspec --profile -- #{argument}`",
                                                         :call_site => nil
                                           true
                                         end
                                       end
        end

        parser.on('--dry-run', 'Print the formatter output of your suite without',
                  '  running any examples or hooks') do |_o|
          options[:dry_run] = true
        end

        parser.on('-w', '--warnings', 'Enable ruby warnings') do
          $VERBOSE = true
        end

        parser.separator <<-FILTERING

  **** Filtering/tags ****

    In addition to the following options for selecting specific files, groups, or
    examples, you can select individual examples by appending the line number(s) to
    the filename:

      rspec path/to/a_spec.rb:37:87

    You can also pass example ids enclosed in square brackets:

      rspec path/to/a_spec.rb[1:5,1:6] # run the 5th and 6th examples/groups defined in the 1st group

FILTERING

        parser.on('--only-failures', "Filter to just the examples that failed the last time they ran.") do
          configure_only_failures(options)
        end

        parser.on("-n", "--next-failure", "Apply `--only-failures` and abort after one failure.",
                  "  (Equivalent to `--only-failures --fail-fast --order defined`)") do
          configure_only_failures(options)
          set_fail_fast(options, 1)
          options[:order] ||= 'defined'
        end

        parser.on('-P', '--pattern PATTERN', 'Load files matching pattern (default: "spec/**/*_spec.rb").') do |o|
          if options[:pattern]
            options[:pattern] += ',' + o
          else
            options[:pattern] = o
          end
        end

        parser.on('--exclude-pattern PATTERN',
                  'Load files except those matching pattern. Opposite effect of --pattern.') do |o|
          options[:exclude_pattern] = o
        end

        parser.on('-e', '--example STRING', "Run examples whose full nested names include STRING (may be",
                  "  used more than once)") do |o|
          (options[:full_description] ||= []) << Regexp.compile(Regexp.escape(o))
        end

        parser.on('-t', '--tag TAG[:VALUE]',
                  'Run examples with the specified tag, or exclude examples',
                  'by adding ~ before the tag.',
                  '  - e.g. ~slow',
                  '  - TAG is always converted to a symbol') do |tag|
          filter_type = tag =~ /^~/ ? :exclusion_filter : :inclusion_filter

          name, value = tag.gsub(/^(~@|~|@)/, '').split(':', 2)
          name = name.to_sym

          parsed_value = case value
                         when  nil        then true # The default value for tags is true
                         when 'true'      then true
                         when 'false'     then false
                         when 'nil'       then nil
                         when /^:/        then value[1..-1].to_sym
                         when /^\d+$/     then Integer(value)
                         when /^\d+.\d+$/ then Float(value)
                         else
                           value
                         end

          add_tag_filter(options, filter_type, name, parsed_value)
        end

        parser.on('--default-path PATH', 'Set the default path where RSpec looks for examples (can',
                  '  be a path to a file or a directory).') do |path|
          options[:default_path] = path
        end

        parser.separator("\n  **** Utility ****\n\n")

        parser.on('--init', 'Initialize your project with RSpec.') do |_cmd|
          options[:runner] = RSpec::Core::Invocations::InitializeProject.new
        end

        parser.on('-v', '--version', 'Display the version.') do
          options[:runner] = RSpec::Core::Invocations::PrintVersion.new
        end

        # These options would otherwise be confusing to users, so we forcibly
        # prevent them from executing.
        #
        #   * --I is too similar to -I.
        #   * -d was a shorthand for --debugger, which is removed, but now would
        #     trigger --default-path.
        invalid_options = %w[-d --I]

        hidden_options = invalid_options + %w[-c]

        parser.on_tail('-h', '--help', "You're looking at it.") do
          options[:runner] = RSpec::Core::Invocations::PrintHelp.new(parser, hidden_options)
        end

        # This prevents usage of the invalid_options.
        invalid_options.each do |option|
          parser.on(option) do
            raise OptionParser::InvalidOption.new
          end
        end
      end
    end
    # rubocop:enable Metrics/AbcSize
    # rubocop:enable MethodLength
    # rubocop:enable CyclomaticComplexity
    # rubocop:enable PerceivedComplexity

    def add_tag_filter(options, filter_type, tag_name, value=true)
      (options[filter_type] ||= {})[tag_name] = value
    end

    def set_fail_fast(options, value)
      options[:fail_fast] = value
    end

    def configure_only_failures(options)
      options[:only_failures] = true
      add_tag_filter(options, :inclusion_filter, :last_run_status, 'failed')
    end
  end
end
