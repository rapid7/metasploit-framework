# frozen_string_literal: true
require 'digest/sha1'
require 'fileutils'

module YARD
  module CLI
    # Default options used in +yard doc+ command.
    class YardocOptions < Templates::TemplateOptions
      # @return [Array<CodeObjects::ExtraFileObject>]
      #   the list of extra files rendered along with objects
      default_attr :files, lambda { [] }

      # @return [String] the default title appended to each generated page
      default_attr :title, "Documentation by YARD #{YARD::VERSION}"

      # @return [Verifier] the default verifier object to filter queries
      default_attr :verifier, lambda { Verifier.new }

      # @return [Serializers::Base] the default serializer for generating output
      #   to disk.
      default_attr :serializer, lambda { Serializers::FileSystemSerializer.new }

      # @return [Symbol] the default output format (:html).
      default_attr :format, :html

      # @return [Boolean] whether the data should be rendered in a single page,
      #   if the template supports it.
      default_attr :onefile, false

      # @return [CodeObjects::ExtraFileObject] the README file object rendered
      #   along with objects
      attr_accessor :readme

      # @return [Array<CodeObjects::Base>] the list of code objects to render
      #   the templates with.
      attr_accessor :objects

      # @return [Numeric] An index value for rendering sequentially related templates
      attr_accessor :index

      # @return [CodeObjects::Base] an extra item to send to a template that is not
      #   the main rendered object
      attr_accessor :item

      # @return [CodeObjects::ExtraFileObject] the file object being rendered.
      #   The +object+ key is not used so that a file may be rendered in the context
      #   of an object's namespace (for generating links).
      attr_accessor :file

      # @return [String] the current locale
      attr_accessor :locale
    end

    # Yardoc is the default YARD CLI command (+yard doc+ and historic +yardoc+
    # executable) used to generate and output (mainly) HTML documentation given
    # a set of source files.
    #
    # == Usage
    #
    # Main usage for this command is:
    #
    #   $ yardoc [options] [source_files [- extra_files]]
    #
    # See +yardoc --help+ for details on valid options.
    #
    # == Options File (+.yardopts+)
    #
    # If a +.yardopts+ file is found in the source directory being processed,
    # YARD will use the contents of the file as arguments to the command,
    # treating newlines as spaces. You can use shell-style quotations to
    # group space delimited arguments, just like on the command line.
    #
    # A valid +.yardopts+ file might look like:
    #
    #   --no-private
    #   --title "My Title"
    #   --exclude foo --exclude bar
    #   lib/**/*.erb
    #   lib/**/*.rb -
    #   HACKING.rdoc LEGAL COPYRIGHT
    #
    # Note that Yardoc also supports the legacy RDoc style +.document+ file,
    # though this file can only specify source globs to parse, not options.
    #
    # == Queries (+--query+)
    #
    # Yardoc supports queries to select specific code objects for which to
    # generate documentation. For example, you might want to generate
    # documentation only for your public API. If you've documented your public
    # methods with +@api public+, you can use the following query to select
    # all of these objects:
    #
    #   --query '@api.text == "public"'
    #
    # Note that the syntax for queries is mostly Ruby with a few syntactic
    # simplifications for meta-data tags. See the {Verifier} class for an
    # overview of this syntax.
    #
    # == Adding Custom Ad-Hoc Meta-data Tags (+--tag+)
    #
    # YARD allows specification of {file:docs/Tags.md meta-data tags}
    # programmatically via the {YARD::Tags::Library} class, but often this is not
    # practical for users writing documentation. To make adding custom tags
    # easier, Yardoc has a few command-line switches for creating basic tags
    # and displaying them in generated HTML output.
    #
    # To specify a custom tag to be displayed in output, use any of the
    # following:
    #
    # * +--tag+ TAG:TITLE
    # * +--name-tag+ TAG:TITLE
    # * +--type-tag+ TAG:TITLE
    # * +--type-name-tag+ TAG:TITLE
    # * +--title-tag+ TAG:TITLE
    #
    # "TAG:TITLE" is of the form: name:"Display Title", for example:
    #
    #   --tag overload:"Overloaded Method"
    #
    # See +yard help doc+ for a description of the various options.
    #
    # Tags added in this way are automatically displayed in output. To add
    # a meta-data tag that does not show up in output, use +--hide-tag TAG+.
    # Note that you can also use this option on existing tags to hide
    # builtin tags, for instance.
    #
    # == Processed Data Storage (+.yardoc+ directory)
    #
    # When Yardoc parses a source directory, it creates a +.yardoc+ directory
    # (by default, override with +-b+) at the root of the project. This directory
    # contains marshal dumps for all raw object data in the source, so that
    # you can access it later for various commands (+stats+, +graph+, etc.).
    # This directory is also used as a cache for any future calls to +yardoc+
    # so as to process only the files which have changed since the last call.
    #
    # When Yardoc uses the cache in subsequent calls to +yardoc+, methods
    # or classes that have been deleted from source since the last parsing
    # will not be erased from the cache (YARD never deletes objects). In such
    # a case, you should wipe the cache and do a clean parsing of the source tree.
    # You can do this by deleting the +.yardoc+ directory manually, or running
    # Yardoc without +--use-cache+ (+-c+).
    #
    # @since 0.2.1
    # @see Verifier
    class Yardoc < YardoptsCommand
      # @return [Hash] the hash of options passed to the template.
      # @see Templates::Engine#render
      attr_reader :options

      # @return [Array<String>] list of Ruby source files to process
      attr_accessor :files

      # @return [Array<String>] list of excluded paths (regexp matches)
      # @since 0.5.3
      attr_accessor :excluded

      # @return [Boolean] whether to use the existing yardoc db if the
      #   .yardoc already exists. Also makes use of file checksums to
      #   parse only changed files.
      attr_accessor :use_cache

      # @return [Boolean] whether objects should be serialized to .yardoc db
      attr_accessor :save_yardoc

      # @return [Boolean] whether to generate output
      attr_accessor :generate

      # @return [Boolean] whether to print a list of objects
      # @since 0.5.5
      attr_accessor :list

      # Keep track of which visibilities are to be shown
      # @return [Array<Symbol>] a list of visibilities
      # @since 0.5.6
      attr_accessor :visibilities

      # Keep track of which APIs are to be shown
      # @return [Array<String>] a list of APIs
      # @since 0.8.1
      attr_accessor :apis

      # Keep track of which APIs are to be hidden
      # @return [Array<String>] a list of APIs to be hidden
      # @since 0.8.7
      attr_accessor :hidden_apis

      # @return [Array<Symbol>] a list of tags to hide from templates
      # @since 0.6.0
      attr_accessor :hidden_tags

      # @return [Boolean] whether to print statistics after parsing
      # @since 0.6.0
      attr_accessor :statistics

      # @return [Array<String>] a list of assets to copy after generation
      # @since 0.6.0
      attr_accessor :assets

      # @return [Boolean] whether markup option was specified
      # @since 0.7.0
      attr_accessor :has_markup

      # @return [Boolean] whether yard exits with error status code if a warning occurs
      attr_accessor :fail_on_warning

      # Creates a new instance of the commandline utility
      def initialize
        super
        @options = YardocOptions.new
        @options.reset_defaults
        @visibilities = [:public]
        @apis = []
        @hidden_apis = []
        @assets = {}
        @excluded = []
        @files = []
        @hidden_tags = []
        @use_cache = false
        @generate = true
        @statistics = true
        @list = false
        @save_yardoc = true
        @has_markup = false
        @fail_on_warning = false

        if defined?(::Encoding) && ::Encoding.respond_to?(:default_external=)
          utf8 = ::Encoding.find('utf-8')

          ::Encoding.default_external = utf8 unless ::Encoding.default_external == utf8
          ::Encoding.default_internal = utf8 unless ::Encoding.default_internal == utf8
        end
      end

      def description
        "Generates documentation"
      end

      # Runs the commandline utility, parsing arguments and generating
      # output if set.
      #
      # @param [Array<String>] args the list of arguments. If the list only
      #   contains a single nil value, skip calling of {#parse_arguments}
      # @return [void]
      def run(*args)
        log.show_progress = true
        if args.empty? || !args.first.nil?
          # fail early if arguments are not valid
          return unless parse_arguments(*args)
        end

        checksums = nil
        if use_cache
          Registry.load
          checksums = Registry.checksums.dup
        end

        if save_yardoc
          Registry.lock_for_writing do
            YARD.parse(files, excluded)
            Registry.save(use_cache)
          end
        else
          YARD.parse(files, excluded)
        end

        if generate
          run_generate(checksums)
          copy_assets
        elsif list
          print_list
        end

        if !list && statistics && log.level < Logger::ERROR
          Registry.load_all
          log.enter_level(Logger::ERROR) do
            Stats.new(false).run(*args)
          end
        end

        abort if fail_on_warning && log.warned

        true
      ensure
        log.show_progress = false
      end

      # Parses commandline arguments
      # @param [Array<String>] args the list of arguments
      # @return [Boolean] whether or not arguments are valid
      # @since 0.5.6
      def parse_arguments(*args)
        super(*args)

        # Last minute modifications
        self.files = Parser::SourceParser::DEFAULT_PATH_GLOB if files.empty?
        files.delete_if {|x| x =~ /\A\s*\Z/ } # remove empty ones
        readme = Dir.glob('README{,*[^~]}').first
        readme ||= Dir.glob(files.first).first if options.onefile
        options.readme ||= CodeObjects::ExtraFileObject.new(readme) if readme
        options.files.unshift(options.readme).uniq! if options.readme

        Tags::Library.visible_tags -= hidden_tags
        add_visibility_verifier
        add_api_verifier

        apply_locale

        # US-ASCII is invalid encoding for onefile
        if defined?(::Encoding) && options.onefile
          if ::Encoding.default_internal == ::Encoding::US_ASCII
            log.warn "--one-file is not compatible with US-ASCII encoding, using ASCII-8BIT"
            ::Encoding.default_external, ::Encoding.default_internal = ['ascii-8bit'] * 2
          end
        end

        if generate && !verify_markup_options
          false
        else
          true
        end
      end

      # The list of all objects to process. Override this method to change
      # which objects YARD should generate documentation for.
      #
      # @deprecated To hide methods use the +@private+ tag instead.
      # @return [Array<CodeObjects::Base>] a list of code objects to process
      def all_objects
        Registry.all(:root, :module, :class)
      end

      private

      # Generates output for objects
      # @param [Hash, nil] checksums if supplied, a list of checkums for files.
      # @return [void]
      # @since 0.5.1
      def run_generate(checksums)
        if checksums
          changed_files = []
          Registry.checksums.each do |file, hash|
            changed_files << file if checksums[file] != hash
          end
        end
        Registry.load_all if use_cache
        objects = run_verifier(all_objects).reject do |object|
          serialized = !options.serializer || options.serializer.exists?(object)
          if checksums && serialized && !object.files.any? {|f, _line| changed_files.include?(f) }
            true
          else
            log.debug "Re-generating object #{object.path}..."
            false
          end
        end
        Templates::Engine.generate(objects, options)
      end

      # Verifies that the markup options are valid before parsing any code.
      # Failing early is better than failing late.
      #
      # @return (see YARD::Templates::Helpers::MarkupHelper#load_markup_provider)
      def verify_markup_options
        result = false
        lvl = has_markup ? log.level : Logger::FATAL
        obj = Struct.new(:options).new(options)
        obj.extend(Templates::Helpers::MarkupHelper)
        options.files.each do |file|
          markup = file.attributes[:markup] || obj.markup_for_file('', file.filename)
          result = obj.load_markup_provider(markup)
          return false if !result && markup != :rdoc
        end
        options.markup = :rdoc unless has_markup
        log.enter_level(lvl) { result = obj.load_markup_provider }
        if !result && !has_markup
          log.warn "Could not load default RDoc formatter, " \
                   "ignoring any markup (install RDoc to get default formatting)."
          options.markup = :none
          true
        else
          result
        end
      end

      # Copies any assets to the output directory
      # @return [void]
      # @since 0.6.0
      def copy_assets
        return unless options.serializer
        outpath = options.serializer.basepath
        assets.each do |from, to|
          to = File.join(outpath, to)
          log.debug "Copying asset '#{from}' to '#{to}'"
          from += '/.' if File.directory?(from)
          FileUtils.cp_r(from, to)
        end
      end

      # Prints a list of all objects
      # @return [void]
      # @since 0.5.5
      def print_list
        Registry.load_all
        run_verifier(Registry.all).
          sort_by {|item| [item.file || '', item.line || 0] }.each do |item|
          log.puts "#{item.file}:#{item.line}: #{item.path}"
        end
      end

      # Adds a set of extra documentation files to be processed
      # @param [Array<String>] files the set of documentation files
      def add_extra_files(*files)
        files.map! {|f| f.include?("*") ? Dir.glob(f) : f }.flatten!
        files.each do |file|
          if extra_file_valid?(file)
            options.files << CodeObjects::ExtraFileObject.new(file)
          end
        end
      end

      # @param file [String] the filename to validate
      # @param check_exists [Boolean] whether the file should exist on disk
      # @return [Boolean] whether the file is allowed to be used
      def extra_file_valid?(file, check_exists = true)
        if file =~ %r{^(?:\.\./|/)}
          log.warn "Invalid file: #{file}"
          false
        elsif check_exists && !File.file?(file)
          log.warn "Could not find file: #{file}"
          false
        else
          true
        end
      end

      # Parses the file arguments into Ruby files and extra files, which are
      # separated by a '-' element.
      #
      # @example Parses a set of Ruby source files
      #   parse_files %w(file1 file2 file3)
      # @example Parses a set of Ruby files with a separator and extra files
      #   parse_files %w(file1 file2 - extrafile1 extrafile2)
      # @param [Array<String>] files the list of files to parse
      # @return [void]
      def parse_files(*files)
        seen_extra_files_marker = false

        files.each do |file|
          if file == "-"
            seen_extra_files_marker = true
            next
          end

          if seen_extra_files_marker
            add_extra_files(file)
          else
            self.files << file
          end
        end
      end

      # Adds verifier rule for visibilities
      # @return [void]
      # @since 0.5.6
      def add_visibility_verifier
        vis_expr = "#{visibilities.uniq.inspect}.include?(object.visibility)"
        options.verifier.add_expressions(vis_expr)
      end

      # Adds verifier rule for APIs
      # @return [void]
      # @since 0.8.1
      def add_api_verifier
        no_api = true if apis.delete('')
        exprs = []

        exprs << "#{apis.uniq.inspect}.include?(@api.text)" unless apis.empty?

        unless hidden_apis.empty?
          exprs << "!#{hidden_apis.uniq.inspect}.include?(@api.text)"
        end

        exprs = !exprs.empty? ? [exprs.join(' && ')] : []
        exprs << "!@api" if no_api

        expr = exprs.join(' || ')
        options.verifier.add_expressions(expr) unless expr.empty?
      end

      # Applies the specified locale to collected objects
      # @return [void]
      # @since 0.8.3
      def apply_locale
        YARD::I18n::Locale.default = options.locale
        options.files.each do |file|
          file.locale = options.locale
        end
      end

      # (see Templates::Helpers::BaseHelper#run_verifier)
      def run_verifier(list)
        options.verifier ? options.verifier.run(list) : list
      end

      # @since 0.6.0
      def add_tag(tag_data, factory_method = nil)
        tag, title = *tag_data.split(':')
        title ||= tag.capitalize
        Tags::Library.define_tag(title, tag.to_sym, factory_method)
        Tags::Library.visible_tags |= [tag.to_sym]
      end

      # Parses commandline options.
      # @param [Array<String>] args each tokenized argument
      def optparse(*args)
        opts = OptionParser.new
        opts.banner = "Usage: yard doc [options] [source_files [- extra_files]]"

        opts.separator "(if a list of source files is omitted, "
        opts.separator "  {lib,app}/**/*.rb ext/**/*.c is used.)"
        opts.separator ""
        opts.separator "Example: yardoc -o documentation/ - FAQ LICENSE"
        opts.separator "  The above example outputs documentation for files in"
        opts.separator "  lib/**/*.rb to documentation/ including the extra files"
        opts.separator "  FAQ and LICENSE."
        opts.separator ""
        opts.separator "A base set of options can be specified by adding a .yardopts"
        opts.separator "file to your base path containing all extra options separated"
        opts.separator "by whitespace."

        general_options(opts)
        output_options(opts)
        tag_options(opts)
        common_options(opts)
        parse_options(opts, args)
        parse_files(*args) unless args.empty?
      end

      # Adds general options
      def general_options(opts)
        opts.separator ""
        opts.separator "General Options:"

        opts.on('-b', '--db FILE', 'Use a specified .yardoc db to load from or save to',
                      '  (defaults to .yardoc)') do |yfile|
          YARD::Registry.yardoc_file = yfile
        end

        opts.on('--[no-]single-db', 'Whether code objects should be stored to single',
                                    '  database file (advanced)') do |use_single_db|
          Registry.single_object_db = use_single_db
        end

        opts.on('-n', '--no-output', 'Only generate .yardoc database, no documentation.') do
          self.generate = false
        end

        opts.on('-c', '--use-cache [FILE]',
                "Use the cached .yardoc db to generate documentation.",
                "  (defaults to no cache)") do |file|
          YARD::Registry.yardoc_file = file if file
          self.use_cache = true
        end

        opts.on('--no-cache', "Clear .yardoc db before parsing source.") do
          self.use_cache = false
        end

        yardopts_options(opts)

        opts.on('--no-save', 'Do not save the parsed data to the yardoc db') do
          self.save_yardoc = false
        end

        opts.on('--exclude REGEXP', 'Ignores a file if it matches path match (regexp)') do |path|
          excluded << path
        end

        opts.on('--fail-on-warning', 'Exit with error status code if a warning occurs') do
          self.fail_on_warning = true
        end
      end

      # Adds output options
      def output_options(opts)
        opts.separator ""
        opts.separator "Output options:"

        opts.on('--one-file', 'Generates output as a single file') do
          options.onefile = true
        end

        opts.on('--list', 'List objects to standard out (implies -n)') do |_format|
          self.generate = false
          self.list = true
        end

        opts.on('--no-public', "Don't show public methods. (default shows public)") do
          visibilities.delete(:public)
        end

        opts.on('--protected', "Show protected methods. (default hides protected)") do
          visibilities.push(:protected)
        end

        opts.on('--private', "Show private methods. (default hides private)") do
          visibilities.push(:private)
        end

        opts.on('--no-private', "Hide objects with @private tag") do
          options.verifier.add_expressions '!object.tag(:private) &&
            (object.namespace.is_a?(CodeObjects::Proxy) || !object.namespace.tag(:private))'
        end

        opts.on('--[no-]api API', 'Generates documentation for a given API',
                                  '(objects which define the correct @api tag).',
                                  'If --no-api is given, displays objects with',
                                  'no @api tag.') do |api|
          api = '' if api == false
          apis.push(api)
        end

        opts.on('--hide-api API', 'Hides given @api tag from documentation') do |api|
          hidden_apis.push(api)
        end

        opts.on('--embed-mixins', "Embeds mixin methods into class documentation") do
          options.embed_mixins << '*'
        end

        opts.on('--embed-mixin [MODULE]', "Embeds mixin methods from a particular",
                                          " module into class documentation") do |mod|
          options.embed_mixins << mod
        end

        opts.on('--no-highlight', "Don't highlight code blocks in output.") do
          options.highlight = false
        end

        opts.on('--default-return TYPE', "Shown if method has no return type. ",
                                         "  (defaults to 'Object')") do |type|
          options.default_return = type
        end

        opts.on('--hide-void-return', "Hides return types specified as 'void'. ",
                                      "  (default is shown)") do
          options.hide_void_return = true
        end

        opts.on('--query QUERY', "Only show objects that match a specific query") do |query|
          next if YARD::Config.options[:safe_mode]
          options.verifier.add_expressions(query.taint)
        end

        opts.on('--title TITLE', 'Add a specific title to HTML documents') do |title|
          options.title = title
        end

        opts.on('-r', '--readme FILE', '--main FILE', 'The readme file used as the title page',
                                                      '  of documentation.') do |readme|
          if extra_file_valid?(readme)
            options.readme = CodeObjects::ExtraFileObject.new(readme)
          end
        end

        opts.on('--files FILE1,FILE2,...', 'Any extra comma separated static files to be ',
                                           '  included (eg. FAQ)') do |files|
          add_extra_files(*files.split(","))
        end

        opts.on('--asset FROM[:TO]', 'A file or directory to copy over to output ',
                                     '  directory after generating') do |asset|
          from, to = *asset.split(':').map {|f| File.cleanpath(f, true) }
          to ||= from
          if extra_file_valid?(from, false) && extra_file_valid?(to, false)
            assets[from] = to
          end
        end

        opts.on('-o', '--output-dir PATH',
                'The output directory. (defaults to ./doc)') do |dir|
          options.serializer.basepath = dir
        end

        opts.on('-m', '--markup MARKUP',
                'Markup style used in documentation, like textile, ',
                '  markdown or rdoc. (defaults to rdoc)') do |markup|
          self.has_markup = true
          options.markup = markup.to_sym
        end

        opts.on('-M', '--markup-provider MARKUP_PROVIDER',
                'Overrides the library used to process markup ',
                '  formatting (specify the gem name)') do |markup_provider|
          options.markup_provider = markup_provider.to_sym
        end

        opts.on('--charset ENC', 'Character set to use when parsing files ',
                                 '  (default is system locale)') do |encoding|
          begin
            if defined?(Encoding) && Encoding.respond_to?(:default_external=)
              Encoding.default_external = encoding
              Encoding.default_internal = encoding
            end
          rescue ArgumentError => e
            raise OptionParser::InvalidOption, e
          end
        end

        opts.on('-t', '--template TEMPLATE',
                'The template to use. (defaults to "default")') do |template|
          options.template = template.to_sym
        end

        opts.on('-p', '--template-path PATH',
                'The template path to look for templates in.',
                '  (used with -t).') do |path|
          next if YARD::Config.options[:safe_mode]
          YARD::Templates::Engine.register_template_path(File.expand_path(path))
        end

        opts.on('-f', '--format FORMAT',
                'The output format for the template.',
                '  (defaults to html)') do |format|
          options.format = format.to_sym
        end

        opts.on('--no-stats', 'Don\'t print statistics') do
          self.statistics = false
        end

        opts.on('--no-progress', 'Don\'t show progress bar') do
          log.show_progress = false
        end

        opts.on('--locale LOCALE',
                'The locale for generated documentation.',
                '  (defaults to en)') do |locale|
          options.locale = locale
        end

        opts.on('--po-dir DIR',
                'The directory that has .po files.',
                "  (defaults to #{YARD::Registry.po_dir})") do |dir|
          YARD::Registry.po_dir = dir
        end
      end

      # Adds tag options
      # @since 0.6.0
      def tag_options(opts)
        opts.separator ""
        opts.separator "Tag options: (TAG:TITLE looks like: 'overload:Overloaded Method')"

        opts.on('--tag TAG:TITLE', 'Registers a new free-form metadata @tag') do |tag|
          add_tag(tag)
        end

        opts.on('--type-tag TAG:TITLE', 'Tag with an optional types field') do |tag|
          add_tag(tag, :with_types)
        end

        opts.on('--type-name-tag TAG:TITLE', 'Tag with optional types and a name field') do |tag|
          add_tag(tag, :with_types_and_name)
        end

        opts.on('--name-tag TAG:TITLE', 'Tag with a name field') do |tag|
          add_tag(tag, :with_name)
        end

        opts.on('--title-tag TAG:TITLE', 'Tag with first line as title field') do |tag|
          add_tag(tag, :with_title_and_text)
        end

        opts.on('--hide-tag TAG', 'Hides a previously defined tag from templates') do |tag|
          self.hidden_tags |= [tag.to_sym]
        end

        opts.on('--transitive-tag TAG', 'Marks a tag as transitive') do |tag|
          Tags::Library.transitive_tags |= [tag.to_sym]
        end

        opts.on('--non-transitive-tag TAG', 'Marks a tag as not transitive') do |tag|
          Tags::Library.transitive_tags -= [tag.to_sym]
        end
      end
    end
  end
end
