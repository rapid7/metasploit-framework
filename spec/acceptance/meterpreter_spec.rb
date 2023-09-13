require 'acceptance_spec_helper'

RSpec.describe 'Meterpreter' do
  include_context 'wait_for_expect'

  # Tests to ensure that Meterpreter is consistent across all implementations/operation systems
  METERPRETER_PAYLOADS = Acceptance::Meterpreter.with_meterpreter_name_merged(
    {
      python: Acceptance::Meterpreter::PYTHON_METERPRETER,
      php: Acceptance::Meterpreter::PHP_METERPRETER,
      java: Acceptance::Meterpreter::JAVA_METERPRETER,
      mettle: Acceptance::Meterpreter::METTLE_METERPRETER,
      windows_meterpreter: Acceptance::Meterpreter::WINDOWS_METERPRETER
    }
  )

  TEST_ENVIRONMENT = AllureRspec.configuration.environment_properties

  let_it_be(:current_platform) { Acceptance::Meterpreter::current_platform }

  # @!attribute [r] port_allocator
  #   @return [Acceptance::PortAllocator]
  let_it_be(:port_allocator) { Acceptance::PortAllocator.new }

  # Driver instance, keeps track of all open processes/payloads/etc, so they can be closed cleanly
  let_it_be(:driver) do
    driver = Acceptance::ConsoleDriver.new
    driver
  end

  # Opens a test console with the test loadpath specified
  # @!attribute [r] console
  #   @return [Acceptance::Console]
  let_it_be(:console) do
    console = driver.open_console

    # Load the test modules
    console.sendline('loadpath test/modules')
    console.recvuntil(/Loaded \d+ modules:[^\n]*\n/)
    console.recvuntil(/\d+ auxiliary modules[^\n]*\n/)
    console.recvuntil(/\d+ exploit modules[^\n]*\n/)
    console.recvuntil(/\d+ post modules[^\n]*\n/)
    console.recvuntil(Acceptance::Console.prompt)

    # Read the remaining console
    # console.sendline "quit -y"
    # console.recv_available

    console
  end

  METERPRETER_PAYLOADS.each do |meterpreter_name, meterpreter_config|
    meterpreter_runtime_name = "#{meterpreter_name}#{ENV.fetch('METERPRETER_RUNTIME_VERSION', '')}"

    describe meterpreter_runtime_name, focus: meterpreter_config[:focus] do
      meterpreter_config[:payloads].each.with_index do |payload_config, payload_config_index|
        describe(
          Acceptance::Meterpreter.human_name_for_payload(payload_config).to_s,
          if: (
            Acceptance::Meterpreter.run_meterpreter?(meterpreter_config) &&
              Acceptance::Meterpreter.supported_platform?(payload_config)
          )
        ) do
          let(:payload) { Acceptance::Payload.new(payload_config) }

          class LocalPath
            attr_reader :path

            def initialize(path)
              @path = path
            end
          end

          let(:session_tlv_logging_file) do
            # LocalPath.new('/tmp/php_session_tlv_log.txt')
            Acceptance::TempChildProcessFile.new("#{payload.name}_session_tlv_logging", 'txt')
          end

          let(:meterpreter_logging_file) do
            # LocalPath.new('/tmp/php_log.txt')
            Acceptance::TempChildProcessFile.new("#{payload.name}_debug_log", 'txt')
          end

          let(:payload_stdout_and_stderr_file) do
            # LocalPath.new('/tmp/php_log.txt')
            Acceptance::TempChildProcessFile.new("#{payload.name}_stdout_and_stderr", 'txt')
          end

          let(:default_global_datastore) do
            {
              SessionTlvLogging: "file:#{session_tlv_logging_file.path}"
            }
          end

          let(:test_environment) { TEST_ENVIRONMENT }

          let(:default_module_datastore) do
            {
              AutoVerifySessionTimeout: ENV['CI'] ? 30 : 10,
              lport: port_allocator.next,
              lhost: '127.0.0.1',
              MeterpreterDebugLogging: "rpath:#{meterpreter_logging_file.path}"
            }
          end

          let(:executed_payload) do
            file = File.open(payload_stdout_and_stderr_file.path, 'w')
            driver.run_payload(
              payload,
              {
                out: file,
                err: file
              }
            )
          end

          # The shared payload process and session instance that will be reused across the test run
          #
          let(:payload_process_and_session_id) do
            console.sendline "use #{payload.name}"
            console.recvuntil(Acceptance::Console.prompt)

            # Set global options
            console.sendline payload.setg_commands(default_global_datastore: default_global_datastore)
            console.recvuntil(Acceptance::Console.prompt)

            # Generate the payload
            console.sendline payload.generate_command(default_module_datastore: default_module_datastore)
            console.recvuntil(/Writing \d+ bytes[^\n]*\n/)
            generate_result = console.recvuntil(Acceptance::Console.prompt)

            expect(generate_result.lines).to_not include(match('generation failed'))
            wait_for_expect do
              expect(payload.size).to be > 0
            end

            console.sendline 'to_handler'
            console.recvuntil(/Started reverse TCP handler[^\n]*\n/)
            payload_process = executed_payload
            session_id = nil

            # Wait for the session to open, or break early if the payload is detected as dead
            wait_for_expect do
              unless payload_process.alive?
                break
              end

              session_opened_matcher = /Meterpreter session (\d+) opened[^\n]*\n/
              session_message = ''
              begin
                session_message = console.recvuntil(session_opened_matcher, timeout: 1)
              rescue Acceptance::ChildProcessRecvError
                # noop
              end

              session_id = session_message[session_opened_matcher, 1]
              expect(session_id).to_not be_nil
            end

            [payload_process, session_id]
          end

          # @param [String] path The file path to read the content of
          # @return [String] The file contents if found
          def get_file_attachment_contents(path)
            return 'none resent' unless File.exists?(path)

            content = File.binread(path)
            content.blank? ? 'file created - but empty' : content
          end

          before :each do |example|
            raise 'Failed to load allure metadata method' unless example.respond_to?(:parameter)

            # Add the test environment metadata to the rspec example instance - so it appears in the final allure report UI
            test_environment.each do |key, value|
              example.parameter(key, value)
            end
          end

          after :all do
            driver.close_payloads
            console.reset
          end

          context "#{Acceptance::Meterpreter.current_platform}" do
            describe "#{Acceptance::Meterpreter.current_platform}/#{meterpreter_runtime_name} Meterpreter successfully opens a session for the #{payload_config[:name].inspect} payload" do
              it(
                "exposes available metasploit commands",
                if: (
                  # Assume that regardless of payload, staged/unstaged/etc, the Meterpreter will have the same commands available
                  # So only run this test when config_index == 0
                  payload_config_index == 0 && Acceptance::Meterpreter.supported_platform?(payload_config)
                  # Run if ENV['METERPRETER'] = 'java php' etc
                  Acceptance::Meterpreter.run_meterpreter?(meterpreter_config) &&
                    # Only run payloads / tests, if the host machine can run them
                    Acceptance::Meterpreter.supported_platform?(payload_config)
                )
              ) do
                begin
                  replication_commands = []
                  current_payload_status = ''

                  # Ensure we have a valid session id; We intentionally omit this from a `before(:each)` to ensure the allure attachments are generated if the session dies
                  payload_process, session_id = payload_process_and_session_id
                  expect(payload_process).to(be_alive, proc do
                    current_payload_status = "Expected Payload process to be running. Instead got: payload process exited with #{payload_process.wait_thread.value} - when running the command #{payload_process.cmd.inspect}"

                    Allure.add_attachment(
                      name: 'Failed payload blob',
                      source: Base64.strict_encode64(File.binread(payload_process.payload_path)),
                      type: Allure::ContentType::TXT
                    )

                    current_payload_status
                  end)
                  expect(session_id).to_not(be_nil, proc do
                    "There should be a session present"
                  end)

                  resource_command = "resource scripts/resource/meterpreter_compatibility.rc"
                  replication_commands << resource_command
                  console.sendline(resource_command)
                  result = console.recvuntil(Acceptance::Console.prompt)

                  available_commands = result.lines(chomp: true).find do |line|
                    line.start_with?("{") && line.end_with?("}") && JSON.parse(line)
                  rescue JSON::ParserError => _e
                    next
                  end
                  expect(available_commands).to_not be_nil

                  available_commands_json = JSON.parse(available_commands, symbolize_names: true)
                  # Generate an allure attachment, a report can be generated afterwards
                  Allure.add_attachment(
                    name: 'available commands',
                    source: JSON.pretty_generate(available_commands_json),
                    type: Allure::ContentType::JSON,
                    test_case: false
                  )
                  expect(available_commands_json[:sessions].length).to be 1
                  expect(available_commands_json[:sessions].first[:commands]).to_not be_empty
                rescue RSpec::Expectations::ExpectationNotMetError, StandardError => e
                  test_run_error = e
                end

                # Test cleanup. We intentionally omit cleanup from an `after(:each)` to ensure the allure attachments are
                # still generated if the session dies in a weird way etc

                # Payload process cleanup / verification
                # The payload process wasn't initially marked as dead - let's close it
                if payload_process.present? && current_payload_status.blank?
                  begin
                    if payload_process.alive?
                      current_payload_status = "Process still alive after running test suite"
                      payload_process.close
                    else
                      current_payload_status = "Expected Payload process to be running. Instead got: payload process exited with #{payload_process.wait_thread.value} - when running the command #{payload_process.cmd.inspect}"
                    end
                  rescue => e
                    Allure.add_attachment(
                      name: 'driver.close_payloads failure information',
                      source: "Error: #{e.class} - #{e.message}\n#{(e.backtrace || []).join("\n")}",
                      type: Allure::ContentType::TXT
                    )
                  end
                end

                console_reset_error = nil
                current_console_data = console.all_data
                begin
                  console.reset
                rescue => e
                  console_reset_error = e
                  Allure.add_attachment(
                    name: 'console.reset failure information',
                    source: "Error: #{e.class} - #{e.message}\n#{(e.backtrace || []).join("\n")}",
                    type: Allure::ContentType::TXT
                  )
                end

                payload_configuration_details = payload.as_readable_text(
                  default_global_datastore: default_global_datastore,
                  default_module_datastore: default_module_datastore
                )

                replication_steps = <<~EOF
                  ## Load test modules
                  loadpath test/modules

                  #{payload_configuration_details}

                  ## Replication commands
                  #{replication_commands.empty? ? 'no additional commands run' : replication_commands.join("\n")}
                EOF

                Allure.add_attachment(
                  name: 'payload configuration and replication',
                  source: replication_steps,
                  type: Allure::ContentType::TXT
                )

                Allure.add_attachment(
                  name: 'payload output if available',
                  source: "Final status:\n#{current_payload_status}\nstdout and stderr:\n#{get_file_attachment_contents(payload_stdout_and_stderr_file.path)}",
                  type: Allure::ContentType::TXT
                )

                Allure.add_attachment(
                  name: 'payload debug log if available',
                  source: get_file_attachment_contents(meterpreter_logging_file.path),
                  type: Allure::ContentType::TXT
                )

                Allure.add_attachment(
                  name: 'session tlv logging if available',
                  source: get_file_attachment_contents(session_tlv_logging_file.path),
                  type: Allure::ContentType::TXT
                )

                Allure.add_attachment(
                  name: 'console data',
                  source: current_console_data,
                  type: Allure::ContentType::TXT
                )

                raise test_run_error if test_run_error
                raise console_reset_error if console_reset_error
              end
            end

            meterpreter_config[:module_tests].each do |module_test|
              describe module_test[:name].to_s, focus: module_test[:focus] do
                it(
                  "#{Acceptance::Meterpreter.current_platform}/#{meterpreter_runtime_name} meterpreter successfully opens a session for the #{payload_config[:name].inspect} payload and passes the #{module_test[:name].inspect} tests",
                  if: (
                    # Run if ENV['METERPRETER'] = 'java php' etc
                    Acceptance::Meterpreter.run_meterpreter?(meterpreter_config) &&
                      # Run if ENV['METERPRETER_MODULE_TEST'] = 'test/cmd_exec' etc
                      Acceptance::Meterpreter.run_meterpreter_module_test?(module_test[:name]) &&
                      # Only run payloads / tests, if the host machine can run them
                      Acceptance::Meterpreter.supported_platform?(payload_config) &&
                      Acceptance::Meterpreter.supported_platform?(module_test) &&
                      # Skip tests that are explicitly skipped, or won't pass in the current environment
                      !Acceptance::Meterpreter.skipped_module_test?(module_test, TEST_ENVIRONMENT)
                  ),
                  # test metadata - will appear in allure report
                  module_test: module_test[:name]
                ) do
                  begin
                    replication_commands = []
                    current_payload_status = ''

                    known_failures = module_test.dig(:lines, :all, :known_failures) || []
                    known_failures += module_test.dig(:lines, current_platform, :known_failures) || []
                    known_failures = known_failures.flat_map { |value| Acceptance::LineValidation.new(*Array(value)).flatten }

                    required_lines = module_test.dig(:lines, :all, :required) || []
                    required_lines += module_test.dig(:lines, current_platform, :required) || []
                    required_lines = required_lines.flat_map { |value| Acceptance::LineValidation.new(*Array(value)).flatten }

                    # Ensure we have a valid session id; We intentionally omit this from a `before(:each)` to ensure the allure attachments are generated if the session dies
                    payload_process, session_id = payload_process_and_session_id

                    expect(payload_process).to(be_alive, proc do
                      current_payload_status = "Expected Payload process to be running. Instead got: payload process exited with #{payload_process.wait_thread.value} - when running the command #{payload_process.cmd.inspect}"

                      Allure.add_attachment(
                        name: 'Failed payload blob',
                        source: Base64.strict_encode64(File.binread(payload_process.payload_path)),
                        type: Allure::ContentType::TXT
                      )

                      current_payload_status
                    end)
                    expect(session_id).to_not(be_nil, proc do
                      "There should be a session present"
                    end)

                    use_module = "use #{module_test[:name]}"
                    run_module = "run session=#{session_id} AddEntropy=true Verbose=true"

                    replication_commands << use_module
                    console.sendline(use_module)
                    console.recvuntil(Acceptance::Console.prompt)

                    replication_commands << run_module
                    console.sendline(run_module)

                    # XXX: When debugging failed tests, you can enter into an interactive msfconsole prompt with:
                    # console.interact

                    # Expect the test module to complete
                    test_result = console.recvuntil('Post module execution completed')

                    # Ensure there are no failures, and assert tests are complete
                    aggregate_failures("#{payload_config[:name].inspect} payload and passes the #{module_test[:name].inspect} tests") do
                      # Skip any ignored lines from the validation input
                      validated_lines = test_result.lines.reject do |line|
                        is_acceptable = known_failures.any? do |acceptable_failure|
                          line.include?(acceptable_failure.value) &&
                            acceptable_failure.if?(test_environment)
                        end || line.match?(/Passed: \d+; Failed: \d+/)

                        is_acceptable
                      end

                      validated_lines.each do |test_line|
                        test_line = Acceptance::Meterpreter.uncolorize(test_line)
                        expect(test_line).to_not include('FAILED', '[-] FAILED', '[-] Exception', '[-] '), "Unexpected error: #{test_line}"
                      end

                      # Assert all expected lines are present
                      required_lines.each do |required|
                        next unless required.if?(test_environment)

                        expect(test_result).to include(required.value)
                      end

                      # Assert all ignored lines are present, if they are not present - they should be removed from
                      # the calling config
                      known_failures.each do |acceptable_failure|
                        next if acceptable_failure.flaky?(test_environment)
                        next unless acceptable_failure.if?(test_environment)

                        expect(test_result).to include(acceptable_failure.value)
                      end
                    end
                  rescue RSpec::Expectations::ExpectationNotMetError, StandardError => e
                    test_run_error = e
                  end

                  # Test cleanup. We intentionally omit cleanup from an `after(:each)` to ensure the allure attachments are
                  # still generated if the session dies in a weird way etc

                  # Payload process cleanup / verification
                  # The payload process wasn't initially marked as dead - let's close it
                  if payload_process.present? && current_payload_status.blank?
                    begin
                      if payload_process.alive?
                        current_payload_status = "Process still alive after running test suite"
                        payload_process.close
                      else
                        current_payload_status = "Expected Payload process to be running. Instead got: payload process exited with #{payload_process.wait_thread.value} - when running the command #{payload_process.cmd.inspect}"
                      end
                    rescue => e
                      Allure.add_attachment(
                        name: 'driver.close_payloads failure information',
                        source: "Error: #{e.class} - #{e.message}\n#{(e.backtrace || []).join("\n")}",
                        type: Allure::ContentType::TXT
                      )
                    end
                  end

                  console_reset_error = nil
                  current_console_data = console.all_data
                  begin
                    console.reset
                  rescue => e
                    console_reset_error = e
                    Allure.add_attachment(
                      name: 'console.reset failure information',
                      source: "Error: #{e.class} - #{e.message}\n#{(e.backtrace || []).join("\n")}",
                      type: Allure::ContentType::TXT
                    )
                  end

                  payload_configuration_details = payload.as_readable_text(
                    default_global_datastore: default_global_datastore,
                    default_module_datastore: default_module_datastore
                  )

                  replication_steps = <<~EOF
                    ## Load test modules
                    loadpath test/modules

                    #{payload_configuration_details}

                    ## Replication commands
                    #{replication_commands.empty? ? 'no additional commands run' : replication_commands.join("\n")}
                  EOF

                  Allure.add_attachment(
                    name: 'payload configuration and replication',
                    source: replication_steps,
                    type: Allure::ContentType::TXT
                  )

                  Allure.add_attachment(
                    name: 'payload output if available',
                    source: "Final status:\n#{current_payload_status}\nstdout and stderr:\n#{get_file_attachment_contents(payload_stdout_and_stderr_file.path)}",
                    type: Allure::ContentType::TXT
                  )

                  Allure.add_attachment(
                    name: 'payload debug log if available',
                    source: get_file_attachment_contents(meterpreter_logging_file.path),
                    type: Allure::ContentType::TXT
                  )

                  Allure.add_attachment(
                    name: 'session tlv logging if available',
                    source: get_file_attachment_contents(session_tlv_logging_file.path),
                    type: Allure::ContentType::TXT
                  )

                  Allure.add_attachment(
                    name: 'console data',
                    source: current_console_data,
                    type: Allure::ContentType::TXT
                  )

                  test_assertions = JSON.pretty_generate(
                    {
                      required_lines: required_lines.map(&:to_h),
                      known_failures: known_failures.map(&:to_h),
                    }
                  )
                  Allure.add_attachment(
                    name: 'test assertions',
                    source: test_assertions,
                    type: Allure::ContentType::TXT
                  )

                  raise test_run_error if test_run_error
                  raise console_reset_error if console_reset_error
                end
              end
            end
          end
        end
      end
    end
  end
end
