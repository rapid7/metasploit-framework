# frozen_string_literal: true
module YARD
  module CLI
    # @since 0.6.0
    class Stats < Yardoc
      include Templates::Helpers::BaseHelper

      # Maintains the order in which +stats_for_+ statistics methods should be
      # printed.
      #
      # @see #print_statistics
      STATS_ORDER = [:files, :modules, :classes, :constants, :attributes, :methods]

      # @return [Boolean] whether to parse and load registry
      attr_accessor :parse

      # @param [Boolean] parse whether to parse and load registry (see {#parse})
      def initialize(parse = true)
        super()
        @parse = parse
        @undoc_list = nil
        @compact = false
      end

      def description
        "Prints documentation statistics on a set of files"
      end

      # Runs the commandline utility, parsing arguments and generating
      # output if set.
      #
      # @param [Array<String>] args the list of arguments
      # @return [void]
      def run(*args)
        parse_arguments(*args)

        if use_cache
          Registry.load!
        elsif parse
          YARD.parse(files, excluded)
          Registry.save(use_cache) if save_yardoc
        end

        print_statistics
        print_undocumented_objects
      end

      # Prints statistics for different object types
      #
      # To add statistics for a specific type, add a method +#stats_for_TYPE+
      # to this class that calls {#output}.
      def print_statistics
        @total = 0
        @undocumented = 0
        meths = methods.map(&:to_s).grep(/^stats_for_/)
        STATS_ORDER.each do |meth|
          mname = "stats_for_#{meth}"
          if meths.include?(mname)
            send(mname)
            meths.delete(mname)
          end
        end
        meths.each {|m| send(m) }

        total =
          if @undocumented == 0
            100
          elsif @total == 0
            0
          else
            (@total - @undocumented).to_f / @total.to_f * 100
          end
        log.puts("% 3.2f%% documented" % total)
      end

      # Prints list of undocumented objects
      def print_undocumented_objects
        return if !@undoc_list || @undoc_list.empty?
        log.puts
        log.puts "Undocumented Objects:"

        # array needed for sort due to unstable sort
        objects = @undoc_list.sort_by {|o| [o.file.to_s, o.path] }
        max = objects.max {|a, b| a.path.length <=> b.path.length }.path.length
        if @compact
          objects.each do |object|
            log.puts("%-#{max}s     (%s)" % [object.path,
              [object.file || "-unknown-", object.line].compact.join(":")])
          end
        else
          last_file = nil
          objects.each do |object|
            if object.file != last_file
              log.puts
              log.puts "(in file: #{object.file || "-unknown-"})"
            end
            log.puts object.path
            last_file = object.file
          end
        end
      end

      # @return [Array<CodeObjects::Base>] all the parsed objects in the registry,
      #   removing any objects that are not visible (private, protected) depending
      #   on the arguments passed to the command.
      def all_objects
        @all_objects ||= run_verifier Registry.all
      end

      # Statistics for files
      def stats_for_files
        files = []
        all_objects.each {|o| files |= [o.file] }
        output "Files", files.size
      end

      # Statistics for modules
      def stats_for_modules
        output "Modules", *type_statistics(:module)
      end

      # Statistics for classes
      def stats_for_classes
        output "Classes", *type_statistics(:class)
      end

      # Statistics for constants
      def stats_for_constants
        output "Constants", *type_statistics(:constant)
      end

      # Statistics for attributes
      def stats_for_attributes
        objs = all_objects.select {|m| m.type == :method && m.is_attribute? }
        objs.uniq! {|m| m.name.to_s.gsub(/=$/, '') }
        undoc = objs.select {|m| m.docstring.blank? }
        @undoc_list |= undoc if @undoc_list
        output "Attributes", objs.size, undoc.size
      end

      # Statistics for methods
      def stats_for_methods
        objs = all_objects.select {|m| m.type == :method }
        objs.reject!(&:is_alias?)
        objs.reject!(&:is_attribute?)
        undoc = objs.select {|m| m.docstring.blank? }
        @undoc_list |= undoc if @undoc_list
        output "Methods", objs.size, undoc.size
      end

      # Prints a statistic to standard out. This method is optimized for
      # getting Integer values, though it allows any data to be printed.
      #
      # @param [String] name the statistic name
      # @param [Integer, String] data the numeric (or any) data representing
      #   the statistic. If +data+ is an Integer, it should represent the
      #   total objects of a type.
      # @param [Integer, nil] undoc number of undocumented objects for the type
      # @return [void]
      def output(name, data, undoc = nil)
        @total += data if data.is_a?(Integer) && undoc
        @undocumented += undoc if undoc.is_a?(Integer)
        data =
          if undoc
            ("%5s (% 5d undocumented)" % [data, undoc])
          else
            "%5s" % data
          end
        log.puts("%-12s %s" % [name + ":", data])
      end

      private

      def type_statistics(type)
        objs = all_objects.select {|m| m.type == type }
        undoc = objs.find_all {|m| m.docstring.blank? }
        @undoc_list |= undoc if @undoc_list
        [objs.size, undoc.size]
      end

      # Parses commandline options.
      # @param [Array<String>] args each tokenized argument
      def optparse(*args)
        opts = OptionParser.new
        opts.banner = "Usage: yard stats [options] [source_files]"

        opts.separator "(if a list of source files is omitted, lib/**/*.rb ext/**/*.c is used.)"

        general_options(opts)
        output_options(opts)
        tag_options(opts)
        common_options(opts)
        parse_options(opts, args)
        parse_files(*args) unless args.empty?
      end

      def general_options(opts)
        super(opts)

        opts.on('--list-undoc', 'List all undocumented objects') do
          @undoc_list = []
        end

        opts.on('--compact', 'Compact undocumented objects listing') do
          @compact = true
        end

        opts.on('--no-public', "Don't include public methods in statistics.") do
          visibilities.delete(:public)
        end

        opts.on('--protected', "Include protected methods in statistics.") do
          visibilities.push(:protected)
        end

        opts.on('--private', "Include private methods in statistics.") do
          visibilities.push(:private)
        end

        opts.on('--no-private', "Don't include objects with @private tag in statistics.") do
          options[:verifier].add_expressions '!object.tag(:private) &&
            (object.namespace.type == :proxy || !object.namespace.tag(:private))'
        end

        opts.on('--query QUERY', "Only includes objects that match a specific query") do |query|
          options[:verifier].add_expressions(query.taint)
        end
      end
    end
  end
end
