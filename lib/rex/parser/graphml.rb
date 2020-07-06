# -*- coding: binary -*-

module Rex
module Parser
module GraphML

  def self.parse(file_path)
    parser = Nokogiri::XML::SAX::Parser.new(Document.new)
    parser.parse(File.read(file_path, mode: 'rb'))
    parser.document.graphml
  end

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
    when :string
    else
      raise ArgumentError.new('Unsupported attribute type: ' + attr_type.to_s)
    end

    value
  end

  class MetaAttribute
    def initialize(id, name, type, domain: :all, default: nil)
      @id = id
      @name = name
      @type = type
      @domain = domain
      @default = default
    end

    def self.from_key(key)
      self.new(key.id, key.attr_name, key.attr_type, domain: key.domain, default: key.default&.value)
    end

    def convert(value)
      GraphML.convert_attribute(@type, value)
    end

    def valid_for?(element)
      @domain == :all || @domain == element.class::ELEMENT_NAME.to_sym
    end

    attr_reader :id
    attr_reader :name
    attr_reader :type
    attr_reader :domain
    attr_reader :default
  end

  class AttributeContainer
    def initialize
      @attributes = {}
    end

    attr_reader :attributes
  end

  module Element
    class Data
      ELEMENT_NAME = 'data'
      def initialize(key)
        @key = key
        @value = nil
      end

      def self.from_xml_attributes(xml_attrs)
        key = xml_attrs['key']
        raise Error::InvalidAttributeError.new('data', 'key') if key.nil?
        self.new(key)
      end

      attr_reader :key
      attr_reader :value
    end

    class Default
      ELEMENT_NAME = 'default'
      def initialize(value: nil)
        @value = value
      end

      def self.from_xml_attributes(xml_attrs)
        self.new # no attributes for this element
      end

      attr_reader :value
    end

    class Edge < AttributeContainer
      ELEMENT_NAME = 'edge'
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
        elsif %w{ true false }.include? directed
          directed = directed == 'true'
        else
          raise Error::InvalidAttributeError.new('edge', 'directed', details: 'must be either true or false when specified', missing: false)
        end

        self.new(source, target, directed, id: xml_attrs['id'])
      end

      attr_reader :source
      attr_reader :target
      attr_reader :directed
      attr_reader :id
    end

    class Graph < AttributeContainer
      ELEMENT_NAME = 'graph'
      def initialize(edgedefault, id: nil)
        @edgedefault = edgedefault
        @id = id

        @nodes = {}
        @edges = []
        super()
      end

      def self.from_xml_attributes(xml_attrs)
        edgedefault = xml_attrs['edgedefault']
        unless %w{ directed undirected }.include? edgedefault
          # see: http://graphml.graphdrawing.org/primer/graphml-primer.html section 2.3.1
          raise Error::InvalidAttributeError.new('graph', 'edgedefault', missing: edgedefault.nil?)
        end
        edgedefault = edgedefault.to_sym

        self.new(edgedefault, id: xml_attrs['id'])
      end

      attr_reader :edgedefault
      attr_reader :id
      attr_reader :edges
      attr_reader :nodes
    end

    class GraphML
      ELEMENT_NAME = 'graphml'
      def initialize
        @nodes = {} # always keyed by id
        @edges = []
        @graphs = []
      end

      attr_reader :nodes
      attr_reader :edges
      attr_reader :graphs
    end

    class Key
      ELEMENT_NAME = 'key'
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
        unless %w{ boolean int long float double string }.include? type
          raise Error::InvalidAttributeError.new('key', 'attr.type', details: 'must be boolean int long float double or string', missing: type.nil?)
        end
        type = type.to_sym

        domain = xml_attrs['for']
        unless %w{ graph node edge all }.include? domain
          raise Error::InvalidAttributeError.new('key', 'for', details: 'must be graph node edge or all', missing: domain.nil?)
        end
        domain = domain.to_sym

        self.new(id, name, type, domain)
      end

      def default=(value)
        @default = GraphML.convert_attribute(@attr_type, value)
      end

      attr_reader :id
      attr_reader :attr_name
      attr_reader :attr_type
      attr_reader :domain
      attr_reader :default
    end

    class Node < AttributeContainer
      ELEMENT_NAME = 'node'
      def initialize(id)
        @id = id
        @edges = []
        super()
      end

      def self.from_xml_attributes(xml_attrs)
        id = xml_attrs['id']
        raise Error::InvalidAttributeError.new('node', 'id') if id.nil?
        self.new(id)
      end

      def source_edges
        # edges connected to this node
        @edges.filter { |edge| edge.target == @id || !edge.directed }
      end

      def target_edges
        # edges connecting this to other nodes
        @edges.filter { |edge| edge.source == @id || !edge.directed }
      end

      attr_reader :id
      attr_reader :edges
    end
  end

  module Error
    class GraphMLError < StandardError
      def initialize(message)
        super
      end
    end

    class ParserError < GraphMLError

    end

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
        raise Error::ParserError.new('The \'data\' element must be a direct child of an attribute container') unless @stack[-1].is_a? AttributeContainer
        element = Element::Data.from_xml_attributes(attrs)

      when 'default'
        raise Error::ParserError.new('The \'default\' element must be a direct child of a \'key\' element') unless @stack[-1].is_a? Element::Key
        element = Element::Default.from_xml_attributes(attrs)

      when 'edge'
        raise Error::ParserError.new('The \'edge\' element must be a direct child of a \'graph\' element') unless @stack[-1].is_a? Element::Graph
        element = Element::Edge.from_xml_attributes(attrs, @stack[-1].edgedefault)
        @graphml.edges << element

      when 'graph'
        element = Element::Graph.from_xml_attributes(attrs)
        @graphml.graphs << element

      when 'graphml'
        element = Element::GraphML.new
        raise Error::ParserError.new('The \'graphml\' element must be a top-level element') unless @stack.empty?
        @graphml = element

      when 'key'
        raise Error::ParserError.new('The \'key\' element must be a direct child of a \'graphml\' element') unless @stack[-1].is_a? Element::GraphML
        element = Element::Key.from_xml_attributes(attrs)
        raise Error::InvalidAttributeError.new('key', 'id', details: 'duplicate key id') if @meta_attributes.key? element.id
        if @meta_attributes.values.any? { |attr| attr.name == element.attr_name }
          raise Error::InvalidAttributeError.new('key', 'attr.name', details: 'duplicate key attr.name')
        end

      when 'node'
        raise Error::ParserError.new('The \'node\' element must be a direct child of a \'graph\' element') unless @stack[-1].is_a? Element::Graph
        element = Element::Node.from_xml_attributes(attrs)
        raise Error::InvalidAttributeError.new('node', 'id', details: 'duplicate node id') if @nodes.key? element.id
        @nodes[element.id] = element
        @graphml.nodes[element.id] = element

      else
        raise Error::ParserError.new('Unknown element: ' + name)

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
          raise Error::ParserError.new("The #{meta_attribute.name} attribute is invalid for #{parent.class::ELEMENT_NAME} elements")
        end
        parent.attributes[meta_attribute.name] = meta_attribute.convert(string)

      when Element::Default
        @stack[-1] = element = Element::Default.new(value: string)

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
          raise InvalidAttributeError.new('edge', 'source', details: 'undefined source', missing: false) if source_node.nil?
          target_node = element.nodes[edge.target]
          raise InvalidAttributeError.new('edge', 'target', details: 'undefined target', missing: false) if target_node.nil?
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
