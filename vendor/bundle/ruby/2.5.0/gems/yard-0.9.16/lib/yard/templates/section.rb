# frozen_string_literal: true
module YARD
  module Templates
    # Abstracts the structure for a section and its subsections into an ordered
    # list of sections and subsections.
    # @since 0.6.0
    class Section < Array
      attr_accessor :name

      def initialize(name, *args)
        self.name = name
        replace(parse_sections(args))
      end

      def dup
        obj = super
        obj.name = name
        obj
      end

      def [](*args)
        if args.first.is_a?(Range) || args.size > 1
          obj = super(*args)
          obj.name = name
          return obj
        elsif args.first.is_a?(Integer)
          return super(*args)
        end
        find {|o| o.name == args.first }
      end

      def eql?(other)
        super(other) && name == other.name
      end

      def ==(other)
        case other
        when Section
          eql?(other)
        when Array
          to_a == other
        else
          name == other
        end
      end

      def push(*args)
        super(*parse_sections(args))
      end
      alias << push

      def unshift(*args)
        super(*parse_sections(args))
      end

      def inspect
        n = name.respond_to?(:path) ? "T('#{name.path}')" : name.inspect
        subsects = empty? ? "" : ", subsections=#{super}"
        "Section(#{n}#{subsects})"
      end

      def place(*args)
        super(*parse_sections(args))
      end

      def to_a
        list = [name]
        unless empty?
          subsects = []
          each {|s| subsects += s.to_a }
          list << subsects
        end
        list
      end

      def any(item)
        find do |section|
          return section if section == item
          return section.any(item) unless section.empty?
        end
        nil
      end

      private

      def parse_sections(args)
        if args.size == 1 && args.first.is_a?(Array) && !args.first.is_a?(Section)
          args = args.first
        end
        sections = []
        args.each_with_index do |name, index|
          case name
          when Section; sections << name
          when Array;   next
          else
            subsections = args[index + 1].is_a?(Array) ? args[index + 1] : []
            subsections = [] if subsections.is_a?(Section)
            sections << Section.new(name, subsections)
          end
        end
        sections
      end
    end
  end
end
