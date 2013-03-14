module Nokogiri
  module CSS
    class Node
      # Get the type of this node
      attr_accessor :type
      # Get the value of this node
      attr_accessor :value

      # Create a new Node with +type+ and +value+
      def initialize type, value
        @type = type
        @value = value
      end

      # Accept +visitor+
      def accept visitor
        visitor.send(:"visit_#{type.to_s.downcase}", self)
      end

      ###
      # Convert this CSS node to xpath with +prefix+ using +visitor+
      def to_xpath prefix = '//', visitor = XPathVisitor.new
        self.preprocess!
        prefix + visitor.accept(self)
      end

      # Preprocess this node tree
      def preprocess!
        ### Deal with nth-child
        matches = find_by_type(
          [:CONDITIONAL_SELECTOR,
            [:ELEMENT_NAME],
            [:PSEUDO_CLASS,
              [:FUNCTION]
            ]
          ]
        )
        matches.each do |match|
          if match.value[1].value[0].value[0] =~ /^nth-(last-)?child/
            tag_name = match.value[0].value.first
            match.value[0].value = ['*']
            match.value[1] = Node.new(:COMBINATOR, [
              match.value[1].value[0],
              Node.new(:FUNCTION, ['self(', tag_name])
            ])
          end
        end

        ### Deal with first-child, last-child
        matches = find_by_type(
          [:CONDITIONAL_SELECTOR,
            [:ELEMENT_NAME], [:PSEUDO_CLASS]
        ])
        matches.each do |match|
          if ['first-child', 'last-child'].include?(match.value[1].value.first)
            which = match.value[1].value.first.gsub(/-\w*$/, '')
            tag_name = match.value[0].value.first
            match.value[0].value = ['*']
            match.value[1] = Node.new(:COMBINATOR, [
              Node.new(:FUNCTION, ["#{which}("]),
              Node.new(:FUNCTION, ['self(', tag_name])
            ])
          elsif 'only-child' == match.value[1].value.first
            tag_name = match.value[0].value.first
            match.value[0].value = ['*']
            match.value[1] = Node.new(:COMBINATOR, [
              Node.new(:FUNCTION, ["#{match.value[1].value.first}("]),
              Node.new(:FUNCTION, ['self(', tag_name])
            ])
          end
        end

        self
      end

      # Find a node by type using +types+
      def find_by_type types
        matches = []
        matches << self if to_type == types
        @value.each do |v|
          matches += v.find_by_type(types) if v.respond_to?(:find_by_type)
        end
        matches
      end

      # Convert to_type
      def to_type
        [@type] + @value.map { |n|
          n.to_type if n.respond_to?(:to_type)
        }.compact
      end

      # Convert to array
      def to_a
        [@type] + @value.map { |n| n.respond_to?(:to_a) ? n.to_a : [n] }
      end
    end
  end
end
