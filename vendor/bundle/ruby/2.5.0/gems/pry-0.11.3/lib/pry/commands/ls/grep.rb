class Pry
  class Command::Ls < Pry::ClassCommand
    class Grep

      def initialize(grep_regexp)
        @grep_regexp = grep_regexp
      end

      def regexp
        proc { |x|
          if x.instance_of?(Array)
            x.grep(@grep_regexp)
          else
            x =~ @grep_regexp
          end
        }
      end

    end
  end
end
