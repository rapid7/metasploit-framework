module Recog
class Verifier
  attr_reader :fingerprints, :reporter

  def initialize(fingerprints, reporter)
    @fingerprints = fingerprints
    @reporter = reporter
  end

  def verify
    reporter.report(fingerprints.count) do
      fingerprints.each do |fp|
        reporter.print_name fp

        fp.verify_params do |status, message|
          case status
          when :warn
            reporter.warning "WARN: #{message}"
          when :fail
            reporter.failure "FAIL: #{message}"
          when :success
            reporter.success(message)
          end
        end
        fp.verify_tests do |status, message|
          case status
          when :warn
            reporter.warning "WARN: #{message}"
          when :fail
            reporter.failure "FAIL: #{message}"
          when :success
            reporter.success(message)
          end
        end
      end
    end
  end
end
end
