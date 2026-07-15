# frozen_string_literal: true

# Shared context for login-scanner acceptance tests (postgres, mysql, mssql, smb, ldap, ssh, ...).
#
# Usage — in your spec file:
#
#   RSpec.describe 'My service sessions and modules' do
#     include_context 'protocol_session_acceptance'
#
#     tests = { ... }  # local variable — the test configuration hash
#
#     run_protocol_session_tests(tests, features: %w[my_session_type])
#   end
#
# The +tests+ hash shape:
#
#   {
#     runtime_name_symbol: {
#       target: {
#         session_module: 'auxiliary/scanner/.../login',
#         type: 'ServiceType',
#         platforms: [:linux, :osx, :windows],
#         session_info_pattern: /ServiceType user @ ip/,  # optional
#         datastore: { global: {}, module: { ... } }
#       },
#       module_tests: [
#         {
#           name: 'auxiliary/...',
#           platforms: [:linux, :osx, :windows],
#           targets: [:session, :rhost],
#           action: 'run',          # optional, defaults to 'run'
#           datastore: { ... },     # optional per-module datastore overrides
#           lines: {
#             all: { required: [...], known_failures: [...] },
#           }
#         },
#       ]
#     }
#   }
#
RSpec.shared_context 'protocol_session_acceptance' do
  include_context 'wait_for_expect'

  let(:allure_test_environment) { AllureRspec.configuration.environment_properties }

  let_it_be(:current_platform) { Acceptance::Session.current_platform }

  # Driver instance — keeps track of all open processes/payloads/etc so they can be closed cleanly
  let_it_be(:driver) { Acceptance::ConsoleDriver.new }

  # Opens a test console with the test loadpath configured.
  # Feature flags are enabled by passing them to run_protocol_session_tests.
  # @!attribute [r] console
  #   @return [Acceptance::Console]
  let_it_be(:console) do
    console = driver.open_console

    console.sendline('loadpath test/modules')
    console.recvuntil(/Loaded \d+ modules:[^\n]*\n/)
    console.recvuntil(/\d+ auxiliary modules[^\n]*\n/)
    console.recvuntil(/\d+ exploit modules[^\n]*\n/)
    console.recvuntil(/\d+ post modules[^\n]*\n/)
    console.recvuntil(Acceptance::Console.prompt)

    console
  end

  # Run the given block in a test harness that handles asserting module results,
  # cleanup, and artifact tracking.
  # Not in a before/after block so allure's report generation attaches to the correct test scope.
  def with_test_harness(module_test)
    begin
      replication_commands = []

      known_failures = module_test.dig(:lines, :all, :known_failures) || []
      known_failures += module_test.dig(:lines, current_platform, :known_failures) || []
      known_failures = known_failures.flat_map { |value| Acceptance::LineValidation.new(*Array(value)).flatten }

      required_lines = module_test.dig(:lines, :all, :required) || []
      required_lines += module_test.dig(:lines, current_platform, :required) || []
      required_lines = required_lines.flat_map { |value| Acceptance::LineValidation.new(*Array(value)).flatten }

      yield replication_commands

      # XXX: When debugging failed tests, you can enter an interactive msfconsole prompt with:
      # console.interact

      module_type = module_test[:name].split('/').first
      completion_string = "#{module_type.capitalize} module execution completed"
      test_result = nil
      if Gem.win_platform?
        begin
          test_result = console.recvuntil(completion_string, timeout: 120)
        rescue Acceptance::ChildProcessRecvError, Acceptance::ChildProcessTimeoutError
          # timed out — fall through to partial output handling below
        end
      else
        10.times do |attempt|
          begin
            # Use 60s per attempt — long enough for legitimate module operations
            # (e.g. SMB scanners that need >10s) but short enough to periodically
            # send SIGINT to unblock genuinely hung channel operations.
            test_result = console.recvuntil(completion_string, timeout: 60)
            break
          rescue Acceptance::ChildProcessRecvError, Acceptance::ChildProcessTimeoutError
            $stdout.puts "[module run] No completion after 60s (attempt #{attempt + 1}/10), sending SIGINT"
            $stdout.flush
            console.interrupt_process
            console.recv_available(timeout: 2)
          end
        end
      end
      if test_result.nil?
        $stdout.puts "[module run] Module did not complete after repeated SIGINT attempts, using partial output"
        $stdout.flush
        test_result = console.recv_available(timeout: 2)
        test_result = '' if test_result.nil?
      end

      aggregate_failures("#{target.type} target and passes the #{module_test[:name].inspect} tests") do
        validated_lines = test_result.lines.reject do |line|
          known_failures.any? do |acceptable_failure|
            is_matching_line = acceptable_failure.value.is_a?(Regexp) ? line.match?(acceptable_failure.value) : line.include?(acceptable_failure.value)
            is_matching_line && acceptable_failure.if?(test_environment)
          end || line.match?(/Passed: \d+; Failed: \d+/)
        end

        validated_lines.each do |test_line|
          test_line = Acceptance::Session.uncolorize(test_line)
          expect(test_line).to_not include('FAILED', '[-] FAILED', '[-] Exception', '[-] '), "Unexpected error: #{test_line}"
        end

        required_lines.each do |required|
          next unless required.if?(test_environment)

          if required.value.is_a?(Regexp)
            expect(test_result).to match(required.value)
          else
            expect(test_result).to include(required.value)
          end
        end

        # If a known_failure is no longer present, remove it from the calling config
        known_failures.each do |acceptable_failure|
          next if acceptable_failure.flaky?(test_environment)
          next unless acceptable_failure.if?(test_environment)

          if acceptable_failure.value.is_a?(Regexp)
            expect(test_result).to match(acceptable_failure.value)
          else
            expect(test_result).to include(acceptable_failure.value)
          end
        end
      end
    rescue RSpec::Expectations::ExpectationNotMetError, StandardError => e
      test_run_error = e
    end

    # Test cleanup — intentionally omitted from after(:each) so allure attachments are
    # still generated if the session dies in a weird way.

    console_reset_error = nil
    current_console_data = console.all_data
    begin
      console.reset
    rescue StandardError => e
      console_reset_error = e
      Allure.add_attachment(
        name: 'console.reset failure information',
        source: "Error: #{e.class} - #{e.message}\n#{(e.backtrace || []).join("\n")}",
        type: Allure::ContentType::TXT
      )
    end

    target_configuration_details = target.as_readable_text(
      default_global_datastore: default_global_datastore,
      default_module_datastore: default_module_datastore
    )

    replication_steps = <<~EOF
      ## Load test modules
      loadpath test/modules

      #{target_configuration_details}

      ## Replication commands
      #{replication_commands.empty? ? '# no additional commands run' : replication_commands.join("\n")}
    EOF

    Allure.add_attachment(
      name: 'payload configuration and replication',
      source: replication_steps,
      type: Allure::ContentType::TXT
    )

    Allure.add_attachment(
      name: 'console data',
      source: current_console_data,
      type: Allure::ContentType::TXT
    )

    Allure.add_attachment(
      name: 'test assertions',
      source: JSON.pretty_generate(
        required_lines: required_lines.map(&:to_h),
        known_failures: known_failures.map(&:to_h)
      ),
      type: Allure::ContentType::TXT
    )

    raise test_run_error if test_run_error
    raise console_reset_error if console_reset_error
  end

  # Defines the full describe/context/it structure for a login-scanner test suite.
  # Call this once at the top level of your RSpec.describe block, passing the tests hash.
  #
  # @param tests [Hash] The test configuration hash (see shared context docs above)
  # @param features [Array<String>] msfconsole feature flags to enable before running tests
  def self.run_protocol_session_tests(tests, features: [])
    # Enable any required feature flags on the shared console
    before(:all) do
      Array(features).each do |feature|
        console.sendline("features set #{feature} true")
        console.recvuntil(Acceptance::Console.prompt)
      end
    end

    tests.each do |runtime_name, test_config|
      runtime_name = "#{runtime_name}#{ENV.fetch('RUNTIME_VERSION', '')}"

      describe "#{Acceptance::Session.current_platform}/#{runtime_name}", focus: test_config[:focus] do
        test_config[:module_tests].each do |module_test|
          describe(
            module_test[:name],
            if: Acceptance::Session.supported_platform?(module_test)
          ) do
            let(:target) { Acceptance::Target.new(test_config[:target]) }
            let(:default_global_datastore) { {} }
            let(:test_environment) { allure_test_environment }
            let(:default_module_datastore) { { lhost: '127.0.0.1' } }

            # The shared session id that will be reused across the test run
            let(:session_id) do
              console.sendline "use #{target.session_module}"
              console.recvuntil(Acceptance::Console.prompt)

              console.sendline target.setg_commands(default_global_datastore: default_global_datastore)
              console.recvuntil(Acceptance::Console.prompt)

              console.sendline target.run_command(default_module_datastore: { PASS_FILE: nil, USER_FILE: nil, CreateSession: true })

              session_id = nil
              # Wait for the session to open, or break early if the payload is detected as dead
              wait_for_expect do
                session_opened_matcher = /#{target.type} session (\d+) opened[^\n]*\n/
                session_message = ''
                begin
                  session_message = console.recvuntil(session_opened_matcher, timeout: 1)
                rescue Acceptance::ChildProcessRecvError
                  # noop
                end

                session_id = session_message[session_opened_matcher, 1]
                expect(session_id).to_not be_nil
              end

              console.recvuntil(Acceptance::Console.prompt)

              if target.session_info_pattern
                console.sendline('sessions')
                sessions_output = console.recvuntil(Acceptance::Console.prompt)
                expect(Acceptance::Session.uncolorize(sessions_output)).to match(target.session_info_pattern)
              end

              session_id
            end

            before :each do |example|
              next unless example.respond_to?(:parameter)

              test_environment.each do |key, value|
                example.parameter(key, value)
              end
            end

            after :all do
              driver.close_payloads
              console.reset
            end

            context 'when targeting a session', if: module_test[:targets].include?(:session) do
              it "#{Acceptance::Session.current_platform}/#{runtime_name} session opens and passes the #{module_test[:name].inspect} tests" do
                with_test_harness(module_test) do |replication_commands|
                  # Intentionally not in before(:each) — ensures allure attachments are generated
                  # if the session dies before the example runs.
                  expect(session_id).to_not(be_nil, proc { 'There should be a session present' })

                  run_command = module_test.fetch(:action, 'run')
                  use_module = "use #{module_test[:name]}"
                  run_module = "#{run_command} session=#{session_id} #{target.datastore_options(default_module_datastore: default_module_datastore.merge(module_test.fetch(:datastore, {})))} Verbose=true"

                  replication_commands << use_module
                  console.sendline(use_module)
                  console.recvuntil(Acceptance::Console.prompt)

                  replication_commands << run_module
                  console.sendline(run_module)

                  # Assertions will happen after this block ends
                end
              end
            end

            context 'when targeting an rhost', if: module_test[:targets].include?(:rhost) do
              it "#{Acceptance::Session.current_platform}/#{runtime_name} rhost opens and passes the #{module_test[:name].inspect} tests" do
                with_test_harness(module_test) do |replication_commands|
                  run_command = module_test.fetch(:action, 'run')
                  use_module = "use #{module_test[:name]}"
                  run_module = "#{run_command} #{target.datastore_options(default_module_datastore: default_module_datastore.merge(module_test.fetch(:datastore, {})))} Verbose=true"

                  replication_commands << use_module
                  console.sendline(use_module)
                  console.recvuntil(Acceptance::Console.prompt)

                  replication_commands << run_module
                  console.sendline(run_module)

                  # Assertions will happen after this block ends
                end
              end
            end
          end
        end
      end
    end
  end
end
