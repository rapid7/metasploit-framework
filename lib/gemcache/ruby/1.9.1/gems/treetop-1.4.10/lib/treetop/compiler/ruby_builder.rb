require 'treetop/ruby_extensions/string'

module Treetop
  module Compiler
    class RubyBuilder
      
      attr_reader :level, :address_space, :ruby
      
      def initialize
        @level = 0
        @address_space = LexicalAddressSpace.new
        @ruby = ""
      end
      
      def <<(ruby_line)              
        return if ruby_line.blank?
        ruby << ruby_line.tabto(level) << "\n"
      end

      def newline
        ruby << "\n"
      end
      
      def indented(depth = 2)
        self.in(depth)
        yield
        self.out(depth)
      end
            
      def class_declaration(name, &block)
        self << "class #{name}"
        indented(&block)
        self << "end"
      end
      
      def module_declaration(name, &block)
        self << "module #{name}"
        indented(&block)
        self << "end"
      end
      
      def method_declaration(name, &block)
        self << "def #{name}"
        indented(&block)
        self << "end"
      end
      
      def assign(left, right)
        if left.instance_of? Array
          self << "#{left.join(', ')} = #{right.join(', ')}"
        else
          self << "#{left} = #{right}"
        end
      end
      
      def extend(var, module_name)
        self << "#{var}.extend(#{module_name})"
      end
      
      def accumulate(left, right)
        self << "#{left} << #{right}"
      end
      
      def if__(condition, &block)
        self << "if #{condition}"
        indented(&block)
      end
      
      def if_(condition, &block)
        if__(condition, &block)
        self << 'end'
      end
      
      def else_(&block)
        self << 'else'
        indented(&block)
        self << 'end'
      end
      
      def loop(&block)
        self << 'loop do'
        indented(&block)
        self << 'end'
      end
      
      def break
        self << 'break'
      end
      
      def in(depth = 2)
        @level += depth
        self
      end
      
      def out(depth = 2)
        @level -= depth
        self
      end
      
      def next_address
        address_space.next_address
      end
      
      def reset_addresses
        address_space.reset_addresses
      end
      
      private
      
      def indent
        " " * level
      end
    end
  end
end
