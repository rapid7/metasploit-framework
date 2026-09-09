module Acceptance::Session
  # @return [Symbol] The current platform
  def self.current_platform
    host_os = RbConfig::CONFIG['host_os']
    case host_os
    when /darwin/
      :osx
    when /mingw/
      :windows
    when /linux/
      :linux
    else
      raise "unknown host_os #{host_os.inspect}"
    end
  end

  # Allows restricting the tests of a specific Meterpreter's test suite with the METERPRETER environment variable
  # @return [TrueClass, FalseClass] True if the given Meterpreter should be run, false otherwise.
  def self.run_meterpreter?(meterpreter_config)
    return true if ENV['SESSION'].blank?

    name = meterpreter_config[:name].to_s
    ENV['SESSION'].include?(name)
  end

  # Allows restricting the tests of a specific Meterpreter's test suite with the METERPRETER environment variable
  # @return [TrueClass, FalseClass] True if the given Meterpreter should be run, false otherwise.
  def self.run_meterpreter_module_test?(module_test)
    return true if ENV['SESSION_MODULE_TEST'].blank?

    ENV['SESSION_MODULE_TEST'].include?(module_test)
  end

  # Allows restricting the tests of a specific session's test suite with the SESSION environment variable
  # @return [TrueClass, FalseClass] True if the given session should be run, false otherwise.
  def self.run_session?(session_config)
    return true if ENV['SESSION'].blank?

    name = session_config[:name].to_s
    ENV['SESSION'].include?("command_shell/#{name}")
  end

  # Allows restricting the tests of a specific session's test suite with the SESSION environment variable
  # @return [TrueClass, FalseClass] True if the given session should be run, false otherwise.
  def self.run_session_module_test?(module_test)
    return true if ENV['SESSION_MODULE_TEST'].blank?

    ENV['SESSION_MODULE_TEST'].include?(module_test)
  end

  # @param [String] string A console string with ANSI escape codes present
  # @return [String] A string with the ANSI escape codes removed
  def self.uncolorize(string)
    string.gsub(/\e\[\d+m/, '')
  end

  # @param [Hash] payload_config
  # @return [Boolean]
  def self.supported_platform?(payload_config)
    payload_config[:platforms].include?(current_platform)
  end

  # @param [Hash] module_test
  # @return [Boolean]
  def self.skipped_module_test?(module_test, test_environment)
    current_platform_requirements = Array(module_test[:platforms].find { |platform| Array(platform)[0] == current_platform })[1] || {}
    module_test.fetch(:skip, false) ||
      self.eval_predicate(current_platform_requirements.fetch(:skip, false), test_environment)
  end

  # @param [Hash] payload_config
  # @return [String] The human readable name for the given payload configuration
  def self.human_name_for_payload(payload_config)
    is_stageless = payload_config[:name].include?('_reverse_tcp')
    is_staged = payload_config[:name].include?('/reverse_tcp')

    details = []
    details << 'stageless' if is_stageless
    details << 'staged' if is_staged
    details << payload_config[:name]

    details.join(' ')
  end

  # @param [Object] hash A hash of key => hash
  # @return [Object] Returns a new hash with the 'key' merged into hash value and all payloads
  def self.with_session_name_merged(hash)
    hash.each_with_object({}) do |(name, config), acc|
      acc[name] = config.merge({ name: name })
    end
  end

  # Evaluates a simple predicate; Similar to Msf::OptCondition.eval_condition
  # @param [TrueClass,FalseClass,Array] value
  # @param [Hash] environment
  # @return [TrueClass, FalseClass] True or false
  def self.eval_predicate(value, environment)
    case value
    when Array
      left_operand, operator, right_operand = value
      # Map values such as `:session_name` to the runtime value
      left_operand = environment[left_operand] if environment.key?(left_operand)
      right_operand = environment[right_operand] if environment.key?(right_operand)

      case operator.to_sym
      when :==
        self.eval_predicate(left_operand, environment) == self.eval_predicate(right_operand, environment)
      when :!=
        self.eval_predicate(left_operand, environment) != self.eval_predicate(right_operand, environment)
      when :or
        self.eval_predicate(left_operand, environment) || self.eval_predicate(right_operand, environment)
      else
        raise "unexpected operator #{operator.inspect}"
      end
    else
      value
    end
  end

  # Output signatures produced when a live session's transport stalls mid-run
  # (the send never gets a response and the post module is aborted) rather than
  # when an assertion genuinely fails. These are transient/environmental — a
  # fresh session on retry typically succeeds — so a run whose ONLY errors match
  # these is eligible to be re-run instead of failed.
  # Rex::TimeoutError originates at lib/rex/post/meterpreter/packet_dispatcher.rb.
  TRANSIENT_SESSION_ERROR_SIGNATURES = [
    'Rex::TimeoutError: Send timed out',
    'Post interrupted by the console user'
  ].freeze

  # A genuine test failure, as emitted by the post/test modules
  # (test/lib/module_test.rb): every failing assertion calls
  # `print_error("FAILED: #{msg}")` inside an `it` block, so the line is emitted
  # WITH the current test-name prefix ("[-] [test name] FAILED: ...") — a plain
  # '[-] FAILED' substring would miss it. Match the '[-]' error glyph followed by
  # the 'FAILED:' token allowing any prefix between them, so both the prefixed and
  # the bare forms are caught. If any of these appear alongside the transient
  # signatures, the run is NOT a clean transient — it must fail, never be retried.
  GENUINE_FAILURE_SIGNATURES = [
    /^\[-\].*FAILED:/
  ].freeze

  # @param [String] text A line, or block of console output, from a module test run
  # @return [TrueClass, FalseClass] True if the text contains a known transient
  #   session-transport timeout signature, false otherwise.
  def self.transient_session_error?(text)
    TRANSIENT_SESSION_ERROR_SIGNATURES.any? { |sig| text.to_s.include?(sig) }
  end

  # Classifies a completed module-test run for retry eligibility. A run is only
  # retryable when it exhibited a transient session error AND produced no genuine
  # failure line — i.e. the transport stalled, it was not a real assertion failure.
  #
  # @param [String] test_result The full captured console output of the run
  # @return [TrueClass, FalseClass] True if the run may be retried on a fresh session.
  def self.retryable_transient_failure?(test_result)
    text = test_result.to_s
    # Match per line: the '[-] ... FAILED:' signature is line-anchored, and a
    # genuine failure on any line disqualifies the whole run from retry.
    genuine = text.each_line.any? do |line|
      GENUINE_FAILURE_SIGNATURES.any? { |sig| line.match?(sig) }
    end
    return false if genuine

    transient_session_error?(text)
  end
end
