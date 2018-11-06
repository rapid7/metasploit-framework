module Recog
class VerifyReporter
  attr_reader :formatter
  attr_reader :success_count, :warning_count, :failure_count

  def initialize(options, formatter)
    @options = options
    @formatter = formatter
    reset_counts
  end

  def report(fingerprint_count)
    reset_counts
    yield self
    summarize(fingerprint_count) unless @options.quiet
  end

  def success(text)
    @success_count += 1
    formatter.success_message("#{padding}#{text}") if detail?
  end

  def warning(text)
    return unless @options.warnings
    @warning_count += 1
    formatter.warning_message("#{padding}#{text}")
  end

  def failure(text)
    @failure_count += 1
    formatter.failure_message("#{padding}#{text}")
  end

  def print_name(fingerprint)
    if detail? && fingerprint.tests.any?
      name = fingerprint.name.empty? ? '[unnamed]' : fingerprint.name
      formatter.status_message("\n#{name}")
    end
  end

  def summarize(fingerprint_count)
    print_fingerprint_count(fingerprint_count) if detail?
    print_summary
  end

  def print_fingerprint_count(count)
    formatter.status_message("\nVerified #{count} fingerprints:")
  end

  def print_summary
    colorize_summary(summary_line)
  end

  private

  def reset_counts
    @success_count = @failure_count = @warning_count = 0
  end

  def detail?
    @options.detail
  end

  def padding
    '   ' if @options.detail
  end

  def summary_line
    summary = "SUMMARY: Test completed with "
    summary << "#{@success_count} successful"
    summary << ", #{@warning_count} warnings"
    summary << ", and #{@failure_count} failures"
    summary
  end

  def colorize_summary(summary)
    if @failure_count > 0
      formatter.failure_message(summary)
    elsif @warning_count > 0
      formatter.warning_message(summary)
    else
      formatter.success_message(summary)
    end
  end
end
end
