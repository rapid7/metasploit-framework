# -*- coding: binary -*-

module Rex
  module Parser
    #
    # A partial implementation of the GraphML specification for loading structured data from an XML file. Notable
    # missing components include GraphML parse meta-data (XML attributes with the "parse" prefix), hyperedges and ports.
    # See: http://graphml.graphdrawing.org/
    #
    module GraphML
      #
      # Load the contents of a GraphML file by parsing it with Nokogiri and returning
      # the top level GraphML structure.
      #
      # @param file_path [String] The file path to load the data from.
      # @return [Rex::Parser::GraphML::Element::GraphML]
      def self.from_file(file_path)
        parser = Nokogiri::XML::SAX::Parser.new(Document.new)
        parser.parse(File.read(file_path, mode: 'rb'))
        parser.document.graphml
      end

      #
      # Convert a GraphML value string into a Ruby value depending on the specified type. Values of int and long will be
      # converted to Ruby integer, while float and double values will be converted to floats. For booleans, values that are
      # either blank or "false" (case-insensitive) will evaluate to Ruby's false, while everything else will be true.
      #
      # @param attr_type [Symbol] The type of the attribute, one of either boolean, int, long, float, double or string.
      # @param value [String] The value to convert into a native Ruby data type.
      def self.convert_attribute(attr_type, value)
        case attr_type
        when :boolean
          value.strip!
          if value.blank?
            value = false
          else
            value = value.downcase != 'false'
          end
        when :int, :long
          value = Integer(value)
        when :float, :double
          value = Float(value)
        when :string # rubocop:disable Lint/EmptyWhen
        else
          raise ArgumentError, 'Unsupported attribute type: ' + attr_type.to_s
        end

        value
      end

      #
      # Define a GraphML attribute including its name, data type, default value and where it can be applied.
      #
      class MetaAttribute
        # @param id [String] The attribute's document identifier.
        # @param name [String] The attribute's name as used by applications.
        # @param type [Symbol] The data type of the attribute, one of either boolean, int, long, float, double or string.
        # @param domain [Symbol] What elements this attribute is valid for, one of either edge, node, graph or all.
        # @param default An optional default value for this attribute.
        def initialize(id, name, type, domain: :all, default: nil)
          @id = id
          @name = name
          @type = type
          @domain = domain
          @default = default
        end

        #
        # Create a new instance from a Key element.
        #
        # @param key [Rex::Parser::GraphML::Element::Key] The key to create a new instance from.
        def self.from_key(key)
          new(key.id, key.attr_name, key.attr_type, domain: key.domain, default: key.default&.value)
        end

        #
        # Convert a value to the type specified by this attribute.
        #
        # @param value The value to convert.
        def convert(value)
          GraphML.convert_attribute(@type, value)
        end

        #
        # Whether or not the attribute is valid for the specified element.
        #
        # @param element [Rex::Parser::GraphML::AttributeContainer] The element to check.
        def valid_for?(element)
          @domain == :all || @domain == element.class::ELEMENT_NAME.to_sym
        end

        # @!attribute id
        #   @return [String] The attribute's document identifier.
        attr_reader :id
        # @!attribute name
        #   @return [String] The attribute's name as used by applications.
        attr_reader :name
        # @!attribute type
        #   @return [Symbol] The data type of the attribute.
        attr_reader :type
        # @!attribute domain
        #   @return [Symbol] What elements this attribute is valid for.
        attr_reader :domain
        # @!attribute default
        #   @return An optional default value for this attribute.
        attr_reader :default
      end

      #
      # A base class for GraphML elements that are capable of storing attributes.
      #
      class AttributeContainer
        def initialize
          @attributes = {}
        end

        # @!attribute attributes
        #   @return [Hash] The defined attributes for the element.
        attr_reader :attributes
      end

      #
      # A module for organizing GraphML elements that define the data structure. Each provides a from_xml_attributes
      # function to create an instance from a hash of XML attributes.
      #
      module Element
        #
        # A data element defines the value of an attribute for the parent XML node.
        # See: http://graphml.graphdrawing.org/specification/xsd.html#element-data
        #
        class Data
          ELEMENT_NAME = 'data'.freeze
          # @param key [String] The identifier of the attribute that this object contains a value for.
          def initialize(key)
            @key = key
            @value = nil
          end

          def self.from_xml_attributes(xml_attrs)
            key = xml_attrs['key']
            raise Error::InvalidAttributeError.new('data', 'key') if key.nil?

            new(key)
          end

          # @!attribute key
          #   @return [String] The identifier of the attribute that this object contains a value for.
          attr_reader :key
          # @!attribute value
          #   @return The value of the attribute.
          attr_reader :value
        end

        #
        # A default element defines the optional default value of an attribute. If not default is specified, per the GraphML
        # specification, the attribute is undefined.
        # See: http://graphml.graphdrawing.org/specification/xsd.html#element-default
        #
        class Default
          ELEMENT_NAME = 'default'.freeze
          # @param value The default attribute value.
          def initialize(value: nil)
            @value = value
          end

          def self.from_xml_attributes(_xml_attrs)
            new # no attributes for this element
          end

          # @!attribute value
          #   @return The default attribute value.
          attr_reader :value
        end

        #
        # An edge element defines a connection between two nodes. Connections are optionally directional.
        # See: http://graphml.graphdrawing.org/specification/xsd.html#element-edge
        #
        class Edge < AttributeContainer
          ELEMENT_NAME = 'edge'.freeze
          # @param source [String] The id of the node that this edge originated from.
          # @param target [String] The id of the node that this edge is destined for.
          # @param directed [Boolean] Whether or not this edge only connects in one direction.
          # @param id [String] The optional, unique identifier of this edge.
          def initialize(source, target, directed, id: nil)
            @source = source
            @target = target
            @directed = directed
            @id = id
            super()
          end

          def self.from_xml_attributes(xml_attrs, edgedefault)
            source = xml_attrs['source']
            raise Error::InvalidAttributeError.new('edge', 'source') if source.nil?

            target = xml_attrs['target']
            raise Error::InvalidAttributeError.new('edge', 'target') if target.nil?

            directed = xml_attrs['directed']
            if directed.nil?
              directed = edgedefault == :directed
            elsif %w[true false].include? directed
              directed = directed == 'true'
            else
              raise Error::InvalidAttributeError.new('edge', 'directed', details: 'must be either true or false when specified', missing: false)
            end

            new(source, target, directed, id: xml_attrs['id'])
          end

          # !@attribute source
          #   @return [String] The id of the node that this edge originated from.
          attr_reader :source
          # !@attribute target
          #   @return [String] The id of the node that this edge is destined for.
          attr_reader :target
          # !@attribute directed
          #   @return [Boolean] Whether or not this edge only connects in one direction.
          attr_reader :directed
          # !@attribute id
          #   @return [String] The optional, unique identifier of this edge.
          attr_reader :id
        end

        #
        # A graph element defines a collection of nodes and edges.
        # See: http://graphml.graphdrawing.org/specification/xsd.html#element-graph
        #
        class Graph < AttributeContainer
          ELEMENT_NAME = 'graph'.freeze
          # @param edgedefault [Boolean] Whether or not edges within this graph should be directional by default.
          # @param id [String] The optional, unique identifier of this graph.
          def initialize(edgedefault, id: nil)
            @edgedefault = edgedefault
            @id = id

            @nodes = {}
            @edges = []
            super()
          end

          def self.from_xml_attributes(xml_attrs)
            edgedefault = xml_attrs['edgedefault']
            unless %w[directed undirected].include? edgedefault
              # see: http://graphml.graphdrawing.org/primer/graphml-primer.html section 2.3.1
              raise Error::InvalidAttributeError.new('graph', 'edgedefault', missing: edgedefault.nil?)
            end

            edgedefault = edgedefault.to_sym

            new(edgedefault, id: xml_attrs['id'])
          end

          # @!attribute edgedefault
          #   @return [Boolean] Whether or not edges within this graph should be directional by default.
          attr_reader :edgedefault
          # @!attribute id
          #   @return [String] The optional, unique identifier of this graph.
          attr_reader :id
          # @!attribute edges
          #   @return [Array] An array of edge elements within this graph.
          attr_reader :edges
          # @!attribute nodes
          #   @return [Hash] A hash of node elements, keyed by their string identifier.
          attr_reader :nodes
        end

        #
        # A graphml element is the root of a GraphML document.
        # See: http://graphml.graphdrawing.org/specification/xsd.html#element-graphml
        #
        class GraphML
          ELEMENT_NAME = 'graphml'.freeze
          def initialize
            @nodes = {}
            @edges = []
            @graphs = []
          end

          # @!attribute nodes
          #   @return [Hash] A hash of all node elements within this GraphML document, keyed by their string identifier.
          attr_reader :nodes
          # @!attribute edges
          #   @return [Array] An array of all edge elements within this GraphML document.
          attr_reader :edges
          # @!attribute graphs
          #   @return [Array] An array of all graph elements within this GraphML document.
          attr_reader :graphs
        end

        #
        # A key element defines the attributes that may be present in a document.
        # See: http://graphml.graphdrawing.org/specification/xsd.html#element-key
        #
        class Key
          ELEMENT_NAME = 'key'.freeze
          # @param id [String] The document identifier of the attribute described by this element.
          # @param name [String] The name (as used by applications) of the attribute described by this element.
          # @param type [Symbol] The data type of the attribute described by this element, one of either boolean, int, long, float, double or string.
          # @param domain [Symbol] What elements the attribute described by this element is valid for, one of either edge, node, graph or all.
          def initialize(id, name, type, domain)
            @id = id
            @attr_name = name
            @attr_type = type
            @domain = domain # using 'for' would cause an awkward keyword conflict
            @default = nil
          end

          def self.from_xml_attributes(xml_attrs)
            id = xml_attrs['id']
            raise Error::InvalidAttributeError.new('key', 'id') if id.nil?

            name = xml_attrs['attr.name']
            raise Error::InvalidAttributeError.new('key', 'attr.name') if name.nil?

            type = xml_attrs['attr.type']
            unless %w[boolean int long float double string].include? type
              raise Error::InvalidAttributeError.new('key', 'attr.type', details: 'must be boolean int long float double or string', missing: type.nil?)
            end

            type = type.to_sym

            domain = xml_attrs['for']
            unless %w[graph node edge all].include? domain
              raise Error::InvalidAttributeError.new('key', 'for', details: 'must be graph node edge or all', missing: domain.nil?)
            end

            domain = domain.to_sym

            new(id, name, type, domain)
          end

          def default=(value)
            @default = GraphML.convert_attribute(@attr_type, value)
          end

          # @!attribute id
          #   @return [String] The document identifier of the attribute described by this element.
          attr_reader :id
          # @!attribute attr_name
          #   @return [String] The name (as used by applications) of the attribute described by this element.
          attr_reader :attr_name
          # @!attribute attr_type
          #   @return [Symbol] The data type of the attribute described by this element.
          attr_reader :attr_type
          # @!attribute domain
          #   @return [Symbol] What elements the attribute described by this element is valid for.
          attr_reader :domain
          # @!attribute default
          #   @return The default value of the attribute described by this element.
          attr_reader :default
        end

        #
        # A node element defines an object within the graph that can have zero or more edges connecting it to other nodes. A
        # node element may contain a graph element.
        #
        class Node < AttributeContainer
          ELEMENT_NAME = 'node'.freeze
          # @param id [String] The unique identifier for this node element.
          def initialize(id)
            @id = id
            @edges = []
            @subgraph = nil
            super()
          end

          def self.from_xml_attributes(xml_attrs)
            id = xml_attrs['id']
            raise Error::InvalidAttributeError.new('node', 'id') if id.nil?

            new(id)
          end

          # @return [Array] An array of all edges for which this node is the target.
          def source_edges
            # edges connected to this node
            @edges.select { |edge| edge.target == @id || !edge.directed }
          end

          # @return [Array] An array of all edges for which this node is the source.
          def target_edges
            # edges connecting this to other nodes
            @edges.select { |edge| edge.source == @id || !edge.directed }
          end

          # @!attribute id
          #   @return [String] The unique identifier for this node.
          attr_reader :id
          # @!attribute edges
          #   @return [Array] An array of all edges for which this node is either the source or the target.
          attr_reader :edges
          # @!attribute subgraph
          #   @return [Graph,nil] A subgraph contained within this node.
          attr_accessor :subgraph
        end
      end

      #
      # A module collecting the errors raised by this parser.
      #
      module Error
        #
        # The base error class for errors raised by this parser.
        #
        class GraphMLError < StandardError
        end

        #
        # An error describing an issue that occurred while parsing the the data structure.
        #
        class ParserError < GraphMLError
        end

        #
        # An error describing an XML attribute that is invalid either because the value is missing or otherwise invalid.
        #
        class InvalidAttributeError < ParserError
          def initialize(element, attribute, details: nil, missing: true)
            @element = element
            @attribute = attribute
            # whether or not the attribute is invalid because it is absent
            @missing = missing

            message = "Element '#{element}' contains an invalid attribute: '#{attribute}'"
            message << " (#{details})" unless details.nil?

            super(message)
          end
        end
      end

      #
      # The top-level document parser.
      #
      class Document < Nokogiri::XML::SAX::Document
        def initialize
          @stack = []
          @nodes = {}
          @meta_attributes = {}
          @graphml = nil
          super
        end

        def start_element(name, attrs = [])
          attrs = attrs.to_h

          case name
          when 'data'
            raise Error::ParserError, 'The \'data\' element must be a direct child of an attribute container' unless @stack[-1].is_a? AttributeContainer

            element = Element::Data.from_xml_attributes(attrs)

          when 'default'
            raise Error::ParserError, 'The \'default\' element must be a direct child of a \'key\' element' unless @stack[-1].is_a? Element::Key

            element = Element::Default.from_xml_attributes(attrs)

          when 'edge'
            raise Error::ParserError, 'The \'edge\' element must be a direct child of a \'graph\' element' unless @stack[-1].is_a? Element::Graph

            element = Element::Edge.from_xml_attributes(attrs, @stack[-1].edgedefault)
            @graphml.edges << element

          when 'graph'
            element = Element::Graph.from_xml_attributes(attrs)
            @stack[-1].subgraph = element if @stack[-1].is_a? Element::Node
            @graphml.graphs << element

          when 'graphml'
            element = Element::GraphML.new
            raise Error::ParserError, 'The \'graphml\' element must be a top-level element' unless @stack.empty?

            @graphml = element

          when 'key'
            raise Error::ParserError, 'The \'key\' element must be a direct child of a \'graphml\' element' unless @stack[-1].is_a? Element::GraphML

            element = Element::Key.from_xml_attributes(attrs)
            raise Error::InvalidAttributeError.new('key', 'id', details: 'duplicate key id') if @meta_attributes.key? element.id
            if @meta_attributes.values.any? { |attr| attr.name == element.attr_name }
              raise Error::InvalidAttributeError.new('key', 'attr.name', details: 'duplicate key attr.name')
            end

          when 'node'
            raise Error::ParserError, 'The \'node\' element must be a direct child of a \'graph\' element' unless @stack[-1].is_a? Element::Graph

            element = Element::Node.from_xml_attributes(attrs)
            raise Error::InvalidAttributeError.new('node', 'id', details: 'duplicate node id') if @nodes.key? element.id

            @nodes[element.id] = element
            @graphml.nodes[element.id] = element

          else
            raise Error::ParserError, 'Unknown element: ' + name

          end

          @stack.push element
        end

        def characters(string)
          element = @stack[-1]
          case element
          when Element::Data
            parent = @stack[-2]
            meta_attribute = @meta_attributes[element.key]
            unless meta_attribute.valid_for? parent
              raise Error::ParserError, "The #{meta_attribute.name} attribute is invalid for #{parent.class::ELEMENT_NAME} elements"
            end

            if meta_attribute.type == :string && !parent.attributes[meta_attribute.name].nil?
              # this may be run multiple times if there is an XML escape sequence in the string to concat the parts together
              parent.attributes[meta_attribute.name] << meta_attribute.convert(string)
            else
              parent.attributes[meta_attribute.name] = meta_attribute.convert(string)
            end

          when Element::Default
            @stack[-1] = Element::Default.new(value: string)

          end
        end

        def end_element(name)
          element = @stack.pop

          populate_element_default_attributes(element) if element.is_a? AttributeContainer

          case name
          when 'default'
            key = @stack[-1]
            key.default = element

          when 'edge'
            graph = @stack[-1]
            graph.edges << element

          when 'graph'
            element.edges.each do |edge|
              source_node = element.nodes[edge.source]
              raise Error::InvalidAttributeError.new('edge', 'source', details: "undefined source: '#{edge.source}'", missing: false) if source_node.nil?

              target_node = element.nodes[edge.target]
              raise Error::InvalidAttributeError.new('edge', 'target', details: "undefined target: '#{edge.target}'", missing: false) if target_node.nil?

              source_node.edges << edge
              target_node.edges << edge
            end

          when 'key'
            meta_attribute = MetaAttribute.from_key(element)
            @meta_attributes[meta_attribute.id] = meta_attribute

          when 'node'
            graph = @stack[-1]
            graph.nodes[element.id] = element

          end
        end

        # @!attribute graphml
        #   @return [Rex::Parser::GraphML::Element::GraphML] The root of the parsed document.
        attr_reader :graphml

        private

        def populate_element_default_attributes(element)
          @meta_attributes.values.each do |meta_attribute|
            next unless meta_attribute.valid_for? element
            next if element.attributes.key? meta_attribute.name
            next if meta_attribute.default.nil?

            element.attributes[meta_attribute.name] = meta_attribute.default
          end
        end
      end
    end
  end
end
