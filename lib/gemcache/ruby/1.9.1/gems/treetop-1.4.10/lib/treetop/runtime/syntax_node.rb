module Treetop
  module Runtime
    class SyntaxNode
      attr_reader :input, :interval
      attr_accessor :parent

      def initialize(input, interval, elements = nil)
        @input = input
        @interval = interval
        @elements = elements
      end

      def elements
        return @elements if terminal?
        # replace the character class placeholders in the sequence (lazy instantiation)
        last_element = nil
        @comprehensive_elements ||= @elements.map do |element|
          if element == true
            index = last_element ? last_element.interval.last : interval.first
            element = SyntaxNode.new(input, index...(index + 1))
          end
          element.parent = self
          last_element = element
        end

        @comprehensive_elements
      end

      def terminal?
        @elements.nil?
      end

      def nonterminal?
        !terminal?
      end

      def text_value
        input[interval]
      end

      def empty?
        interval.first == interval.last && interval.exclude_end?
      end
      
      def <=>(other)
        self.interval.first <=> other.interval.first
      end

      def extension_modules
        local_extensions =
          class <<self
            included_modules-Object.included_modules
          end
        if local_extensions.size > 0
          local_extensions
        else
          []    # There weren't any; must be a literal node
        end
      end

      def inspect(indent="")
        em = extension_modules
        interesting_methods = methods-[em.last ? em.last.methods : nil]-self.class.instance_methods
        im = interesting_methods.size > 0 ? " (#{interesting_methods.join(",")})" : ""
        tv = text_value
        tv = "...#{tv[-20..-1]}" if tv.size > 20

        indent +
        self.class.to_s.sub(/.*:/,'') +
          em.map{|m| "+"+m.to_s.sub(/.*:/,'')}*"" +
          " offset=#{interval.first}" +
          ", #{tv.inspect}" +
          im +
          (elements && elements.size > 0 ?
            ":" +
              (elements||[]).map{|e|
          begin
            "\n"+e.inspect(indent+"  ")
          rescue  # Defend against inspect not taking a parameter
            "\n"+indent+" "+e.inspect
          end
              }.join("") :
            ""
          )
      end

      @@dot_id_counter = 0

      def dot_id
        @dot_id ||= @@dot_id_counter += 1
      end

      def write_dot(io)
        io.puts "node#{dot_id} [label=\"'#{text_value}'\"];"
        if nonterminal? then
          elements.each do
            |x|
            io.puts "node#{dot_id} -> node#{x.dot_id};"
            x.write_dot(io)
          end
        end
      end

      def write_dot_file(fname)
        File.open(fname + ".dot","w") do
          |file|
          file.puts "digraph G {"
          write_dot(file)
          file.puts "}"
        end
      end
    end
  end
end
