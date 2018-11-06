# frozen_string_literal: true
module YARD
  module CLI
    # Options to pass to the {Graph} CLI.
    class GraphOptions < Templates::TemplateOptions
      # @return [:dot] the default output format
      default_attr :format, :dot

      # @return [Boolean] whether to list the full class diagram
      attr_accessor :full

      # @return [Boolean] whether to show the object dependencies
      attr_accessor :dependencies

      # @return [String] any contents to pass to the digraph
      attr_accessor :contents
    end

    # A command-line utility to generate Graphviz graphs from
    # a set of objects
    #
    # @see Graph#run
    # @since 0.6.0
    class Graph < YardoptsCommand
      # The options parsed out of the commandline.
      # Default options are:
      #   :format => :dot
      attr_reader :options

      # The set of objects to include in the graph.
      attr_reader :objects

      # Creates a new instance of the command-line utility
      def initialize
        super
        @use_document_file = false
        @options = GraphOptions.new
        options.reset_defaults
        options.serializer = YARD::Serializers::StdoutSerializer.new
      end

      def description
        "Graphs class diagram using Graphviz"
      end

      # Runs the command-line utility.
      #
      # @example
      #   grapher = Graph.new
      #   grapher.run('--private')
      # @param [Array<String>] args each tokenized argument
      def run(*args)
        parse_arguments(*args)

        contents = objects.map do |o|
          o.format(options.merge(:serialize => false))
        end.join("\n")
        opts = {:type => :layout, :contents => contents}
        options.update(opts)
        Templates::Engine.render(options)
      end

      private

      def unrecognized_option(err) end

      # Parses commandline options.
      # @param [Array<String>] args each tokenized argument
      def optparse(*args)
        visibilities = [:public]
        opts = OptionParser.new

        opts.separator ""
        opts.separator "General Options:"

        opts.on('-b', '--db FILE', 'Use a specified .yardoc db to load from or save to. (defaults to .yardoc)') do |yfile|
          YARD::Registry.yardoc_file = yfile
        end

        opts.on('--full', 'Full class diagrams (show methods and attributes).') do
          options[:full] = true
        end

        opts.on('-d', '--dependencies', 'Show mixins in dependency graph.') do
          options[:dependencies] = true
        end

        opts.on('--no-public', "Don't show public methods. (default shows public)") do
          visibilities.delete(:public)
        end

        opts.on('--protected', "Show or don't show protected methods. (default hides protected)") do
          visibilities.push(:protected)
        end

        opts.on('--private', "Show or don't show private methods. (default hides private)") do
          visibilities.push(:private)
        end

        opts.separator ""
        opts.separator "Output options:"

        opts.on('--dot [OPTIONS]', 'Send the results directly to `dot` with optional arguments.') do |dotopts|
          options.serializer = Serializers::ProcessSerializer.new('dot ' + dotopts.to_s)
        end

        opts.on('-f', '--file [FILE]', 'Writes output to a file instead of stdout.') do |file|
          options.serializer = Serializers::FileSystemSerializer.new(:basepath => '.', :extension => nil)
          options.serializer.instance_eval "def serialized_path(object) #{file.inspect} end"
        end

        common_options(opts)
        parse_options(opts, args)

        Registry.load

        expression = "#{visibilities.uniq.inspect}.include?(object.visibility)"
        options.verifier = Verifier.new(expression)
        @objects = args.first ?
          args.map {|o| Registry.at(o) }.compact :
          [Registry.root]
      end
    end
  end
end
