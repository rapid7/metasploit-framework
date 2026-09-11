# frozen_string_literal: true

require 'rspec'
require_relative 'session'

RSpec.describe Acceptance::Session do
  # The transport-stall cascade observed in CI: every send times out, then the
  # post module is aborted. No genuine assertion failure line is present.
  let(:transient_timeout_output) do
    <<~OUTPUT
      [*] use post/test/file
      [read] [-] [should write binary data] Exception: Rex::TimeoutError: Send timed out
      [read] [-] [should read the binary data we just wrote] Exception: Rex::TimeoutError: Send timed out
      [read] [-] Post interrupted by the console user
    OUTPUT
  end

  let(:genuine_failure_output) do
    # Real harness form: print_error("FAILED: ...") fires inside an `it` block, so
    # the test-name prefix is prepended before the '[-]' error glyph's payload.
    <<~OUTPUT
      [*] use post/test/file
      [+] [should write binary data] Passed
      [-] [should read the binary data we just wrote] FAILED: should read the binary data we just wrote
    OUTPUT
  end

  # A run that both stalled AND recorded a real (prefixed) failure must not be retried.
  let(:mixed_output) do
    <<~OUTPUT
      [-] [should write binary data] FAILED: should write binary data
      [read] [-] [should read the binary data we just wrote] Exception: Rex::TimeoutError: Send timed out
    OUTPUT
  end

  let(:clean_pass_output) do
    <<~OUTPUT
      [*] use post/test/file
      [+] [should write binary data] Passed
      Passed: 12; Failed: 0
      [*] Post module execution completed
    OUTPUT
  end

  describe '.transient_session_error?' do
    it 'is true for a Send timed out signature' do
      expect(described_class.transient_session_error?(transient_timeout_output)).to be(true)
    end

    it 'is true for a Post interrupted by the console user signature' do
      expect(described_class.transient_session_error?('[-] Post interrupted by the console user')).to be(true)
    end

    it 'is false for a clean passing run' do
      expect(described_class.transient_session_error?(clean_pass_output)).to be(false)
    end

    it 'is false for a genuine assertion failure with no transient signature' do
      expect(described_class.transient_session_error?(genuine_failure_output)).to be(false)
    end

    it 'is false for nil input' do
      expect(described_class.transient_session_error?(nil)).to be(false)
    end
  end

  describe '.retryable_transient_failure?' do
    it 'is true when only transient timeout errors are present' do
      expect(described_class.retryable_transient_failure?(transient_timeout_output)).to be(true)
    end

    it 'is false for a clean passing run (nothing to retry)' do
      expect(described_class.retryable_transient_failure?(clean_pass_output)).to be(false)
    end

    it 'is false for a genuine failure (must not be retried)' do
      expect(described_class.retryable_transient_failure?(genuine_failure_output)).to be(false)
    end

    it 'is false when a genuine failure coexists with a transient error (never mask a real defect)' do
      expect(described_class.retryable_transient_failure?(mixed_output)).to be(false)
    end

    it 'is false for a bare (no test-name prefix) FAILED line' do
      bare = "[read] [-] [-] Post interrupted by the console user\n[-] FAILED: something broke\n"
      expect(described_class.retryable_transient_failure?(bare)).to be(false)
    end

    it 'does not treat the "Failed: N" summary line as a genuine failure' do
      # The summary line ("Passed: N; Failed: N") is not a "FAILED:" assertion line;
      # a clean transient run whose summary reports failures-from-timeouts stays retryable.
      summary_only = "[read] [-] Post interrupted by the console user\n[-] Passed: 11; Failed: 1; Skipped: 0\n"
      expect(described_class.retryable_transient_failure?(summary_only)).to be(true)
    end
  end
end
