# frozen_string_literal: true

if defined?(JRUBY_VERSION) && JRUBY_VERSION.to_f < 1.7
  require "jruby"
  java_import "org.jruby.ast.NodeType"

  # Coverage for JRuby < 1.7.0 does not work correctly
  #
  #  - does not distinguish lines that cannot be executed
  #  - does (partial) coverage for files loaded before `Coverage.start`.
  #  - does not expand a path like `lib/../spec` to `spec`.
  #
  # This monkey patches Coverage to address those issues
  module Coverage
    class << self
      alias __broken_result__ result

      def result # rubocop:disable Metrics/MethodLength
        fixed = {}
        __broken_result__.each do |path, executed_lines|
          next unless File.file? path

          covered_lines = executed_lines.dup

          process = lambda do |node|
            if node.node_type == NodeType::NEWLINENODE
              pos = node.position
              covered_lines[pos.line] ||= 0
            end
            node.child_nodes.each(&process)
          end

          process[JRuby.parse(File.read(path), path)]

          if (first = covered_lines.detect { |x| x }) && first > 0
            fixed[File.expand_path(path)] = covered_lines
          end
        end

        fixed
      end
    end
  end
end
