# frozen_string_literal: true
require File.dirname(__FILE__) + "/spec_helper"

RSpec.describe YARD::Templates::Engine.template(:default, :constant) do
  describe "fully dressed constant" do
    it "renders text format correctly" do
      YARD.parse_string <<-'eof'
        class YARD::CLI::YRI
          # Default search paths that should be loaded dynamically into YRI. These paths
          # take precedence over all other paths ({SEARCH_PATHS_FILE} and RubyGems
          # paths). To add a path, call:
          #
          #   DEFAULT_SEARCH_PATHS.push("/path/to/.yardoc")
          #
          # @return [Array<String>] a list of extra search paths
          # @since 0.6.0
          DEFAULT_SEARCH_PATHS = []
        end
      eof
      text_equals(Registry.at('YARD::CLI::YRI::DEFAULT_SEARCH_PATHS').format(text_options), :constant001)
    end
  end

  describe "simple constant with no documentation" do
    it "renders text format correctly" do
      # Short constant should show on single line
      YARD.parse_string <<-'eof'
        MYCONST = 'foo'
      eof
      text_equals(Registry.at('MYCONST').format(text_options), :constant002)

      # Long constant should show on multiple lines, indented
      YARD.parse_string <<-'eof'
        MYCONST = [A, B, C, D, E, F, G, H, I, J, K, L,
          M, N, O, P, Q, R, S, T, U, V, W,
          X, Y, Z]
      eof
      text_equals(Registry.at('MYCONST').format(text_options), :constant003)
    end
  end
end
