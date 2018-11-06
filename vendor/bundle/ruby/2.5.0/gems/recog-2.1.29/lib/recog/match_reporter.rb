module Recog
class MatchReporter
  attr_reader :formatter
  attr_reader :line_count, :match_count, :fail_count

  def initialize(options, formatter)
    @options = options
    @formatter = formatter
    reset_counts
  end

  def report
    reset_counts
    yield self
    summarize unless @options.quiet
  end

  def stop?
    return false unless @options.fail_fast
    @fail_count >= @options.stop_after
  end

  def increment_line_count
    @line_count += 1
  end

  def match(text)
    @match_count += 1
    formatter.success_message(text)
  end

  def failure(text)
    @fail_count += 1
    formatter.failure_message(text)
  end

  def print_summary
    colorize_summary(summary_line)
  end

  private

  def reset_counts
    @line_count = @match_count = @fail_count = 0
  end

  def detail?
    @options.detail
  end

  def summarize
    if detail?
      print_lines_processed
      print_summary
    end
  end

  def print_lines_processed
    formatter.status_message("\nProcessed #{line_count} lines")
  end

  def summary_line
    summary = "SUMMARY: "
    summary << "#{match_count} matches"
    summary << " and #{fail_count} failures"
    summary
  end

  def colorize_summary(summary)
    if @fail_count > 0
      formatter.failure_message(summary)
    else
      formatter.success_message(summary)
    end
  end
end
end
