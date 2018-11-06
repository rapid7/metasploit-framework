# frozen_string_literal: true
module YARD
  module Parser
    # Represents the abstract base parser class that parses source code in
    # a specific way. A parser should implement {#parse}, {#tokenize} and
    # {#enumerator}.
    #
    # == Registering a Custom Parser
    # To register a parser, see {SourceParser.register_parser_type}
    #
    # @abstract
    # @see #parse
    # @see #tokenize
    # @see #enumerator
    # @since 0.5.6
    class Base
      # Convenience method to create a new parser and {#parse}
      def self.parse(source, filename = nil)
        new(source, filename).parse
      end

      # This default constructor does nothing. The subclass is responsible for
      # storing the source contents and filename if they are required.
      # @param [String] source the source contents
      # @param [String] filename the name of the file if from disk
      def initialize(source, filename) # rubocop:disable Lint/UnusedMethodArgument
        raise NotImplementedError, "invalid parser implementation"
      end

      # This method should be implemented to parse the source and return itself.
      # @abstract
      # @return [Base] this method should return itself
      def parse
        raise NotImplementedError, "#{self.class} must implement #parse"
      end

      # This method should be implemented to tokenize given source
      # @abstract
      # @return [Array] a list/tree of lexical tokens
      def tokenize
        raise NotImplementedError, "#{self.class} does not support tokenization"
      end

      # This method should be implemented to return a list of semantic tokens
      # representing the source code to be post-processed. Otherwise the method
      # should return nil.
      #
      # @abstract
      # @return [Array] a list of semantic tokens representing the source code
      #   to be post-processed
      # @return [nil] if no post-processing should be done
      def enumerator
        nil
      end
    end
  end
end
