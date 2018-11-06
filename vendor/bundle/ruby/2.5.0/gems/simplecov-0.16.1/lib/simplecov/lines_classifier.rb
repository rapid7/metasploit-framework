# frozen_string_literal: true

module SimpleCov
  # Classifies whether lines are relevant for code coverage analysis.
  # Comments & whitespace lines, and :nocov: token blocks, are considered not relevant.

  class LinesClassifier
    RELEVANT = 0
    NOT_RELEVANT = nil

    WHITESPACE_LINE = /^\s*$/
    COMMENT_LINE = /^\s*#/
    WHITESPACE_OR_COMMENT_LINE = Regexp.union(WHITESPACE_LINE, COMMENT_LINE)

    def self.no_cov_line
      /^(\s*)#(\s*)(\:#{SimpleCov.nocov_token}\:)/o
    end

    def self.no_cov_line?(line)
      line =~ no_cov_line
    rescue ArgumentError
      # E.g., line contains an invalid byte sequence in UTF-8
      false
    end

    def self.whitespace_line?(line)
      line =~ WHITESPACE_OR_COMMENT_LINE
    rescue ArgumentError
      # E.g., line contains an invalid byte sequence in UTF-8
      false
    end

    def classify(lines)
      skipping = false

      lines.map do |line|
        if self.class.no_cov_line?(line)
          skipping = !skipping
          NOT_RELEVANT
        elsif skipping || self.class.whitespace_line?(line)
          NOT_RELEVANT
        else
          RELEVANT
        end
      end
    end
  end
end
