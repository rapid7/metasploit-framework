require 'acceptance_spec_helper'

RSpec.describe 'LDAP modules' do
  include_context 'wait_for_expect'

  RHOST_REGEX = /\d+\.\d+\.\d+\.\d+:\d+/

  tests = {
    ldap: {
      target: {
        session_module: 'auxiliary/scanner/ldap/ldap_login',
        type: 'LDAP',
        platforms: %i[linux osx windows],
        datastore: {
          global: {},
          module: {
            ldapusername: ENV.fetch('LDAP_LDAPUsername', "'DEV-AD\\Administrator'"),
            ldappassword: ENV.fetch('LDAP_LDAPPassword', 'admin123!'),
            rhost: ENV.fetch('LDAP_RHOST', '127.0.0.1'),
            rport: ENV.fetch('LDAP_RPORT', '389'),
            ssl: ENV.fetch('LDAP_SSL', 'false')
          }
        }
      },
      module_tests: [
        {
          name: 'auxiliary/gather/ldap_query',
          platforms: %i[linux osx windows],
          targets: [:session, :rhost],
          skipped: false,
          action: 'run_query_file',
          datastore: { QUERY_FILE_PATH: 'data/auxiliary/gather/ldap_query/ldap_queries_default.yaml' },
          lines: {
            all: {
              required: [
                /Loading queries from/,
                /ldap_queries_default.yaml.../,
                /Discovered base DN/,
                /Running ENUM_ACCOUNTS.../,
                /Running ENUM_USER_SPNS_KERBEROAST.../,
                /Running ENUM_USER_PASSWORD_NOT_REQUIRED.../,
              ]
            }
          }
        },
        {
          name: 'auxiliary/gather/ldap_query',
          platforms: %i[linux osx windows],
          targets: [:session, :rhost],
          skipped: false,
          action: 'enum_accounts',
          lines: {
            all: {
              required: [
                /Discovered base DN/,
                /Query returned 4 results/
              ]
            }
          }
        },
        {
          name: 'auxiliary/gather/ldap_hashdump',
          platforms: %i[linux osx windows],
          targets: [:session, :rhost],
          skipped: false,
          lines: {
            all: {
              required: [
                /Searching base DN='DC=ldap,DC=example,DC=com'/,
                /Storing LDAP data for base DN='DC=ldap,DC=example,DC=com' in loot/,
                /266 entries, 0 creds found in 'DC=ldap,DC=example,DC=com'./
              ]
            }
          }
        },
        {
          name: 'auxiliary/admin/ldap/shadow_credentials',
          platforms: %i[linux osx windows],
          targets: [:session, :rhost],
          skipped: false,
          datastore: { TARGET_USER: 'administrator' },
          lines: {
            all: {
              required: [
                /Discovered base DN: DC=ldap,DC=example,DC=com/,
                /The msDS-KeyCredentialLink field is empty./
              ]
            }
          }
        },
        {
          name: 'auxiliary/gather/ldap_esc_vulnerable_cert_finder',
          platforms: %i[linux osx windows],
          targets: [:session, :rhost],
          skipped: false,
          lines: {
            all: {
              required: [
                /Successfully queried/
              ]
            },
            linux: {
              known_failures: [
                /Auxiliary aborted due to failure: not-found/
              ]
            }
          }
        },
        {
          name: 'auxiliary/admin/ldap/rbcd',
          platforms: %i[linux osx windows],
          targets: [:session, :rhost],
          skipped: false,
          datastore: { DELEGATE_TO: 'administrator' },
          lines: {
            all: {
              required: [
                /The msDS-AllowedToActOnBehalfOfOtherIdentity field is empty./
              ]
            }
          }
        },
      ]
    }
  }

  allure_test_environment = AllureRspec.configuration.environment_properties

  let_it_be(:current_platform) { Acceptance::Session.current_platform }

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

    features = %w[
      ldap_session_type
    ]

    features.each do |feature|
      console.sendline("features set #{feature} true")
      console.recvuntil(Acceptance::Console.prompt)
    end

    console
  end

  # Run the given block in a 'test harness' which will handle all of the boilerplate for asserting module results, cleanup, and artifact tracking
  # This doesn't happen in a before/after block to ensure that allure's report generation is correctly attached to the correct test scope
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

      # XXX: When debugging failed tests, you can enter into an interactive msfconsole prompt with:
      # console.interact

      # Expect the test module to complete
      module_type = module_test[:name].split('/').first
      test_result = console.recvuntil("#{module_type.capitalize} module execution completed")

      # Ensure there are no failures, and assert tests are complete
      aggregate_failures("#{target.type} target and passes the #{module_test[:name].inspect} tests") do
        # Skip any ignored lines from the validation input
        validated_lines = test_result.lines.reject do |line|
          is_acceptable = known_failures.any? do |acceptable_failure|
            is_matching_line = acceptable_failure.value.is_a?(Regexp) ? line.match?(acceptable_failure.value) : line.include?(acceptable_failure.value)
            is_matching_line &&
              acceptable_failure.if?(test_environment)
          end || line.match?(/Passed: \d+; Failed: \d+/)

          is_acceptable
        end

        validated_lines.each do |test_line|
          test_line = Acceptance::Session.uncolorize(test_line)
          expect(test_line).to_not include('FAILED', '[-] FAILED', '[-] Exception', '[-] '), "Unexpected error: #{test_line}"
        end

        # Assert all expected lines are present
        required_lines.each do |required|
          next unless required.if?(test_environment)

          if required.value.is_a?(Regexp)
            expect(test_result).to match(required.value)
          else
            expect(test_result).to include(required.value)
          end
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
      #{replication_commands.empty? ? 'no additional commands run' : replication_commands.join("\n")}
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

    test_assertions = JSON.pretty_generate(
      {
        required_lines: required_lines.map(&:to_h),
        known_failures: known_failures.map(&:to_h)
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

  tests.each do |runtime_name, test_config|
    runtime_name = "#{runtime_name}#{ENV.fetch('RUNTIME_VERSION', '')}"

    describe "#{Acceptance::Session.current_platform}/#{runtime_name}", focus: test_config[:focus] do
      test_config[:module_tests].each do |module_test|
        describe(
          module_test[:name],
          if:
            Acceptance::Session.supported_platform?(module_test)
        ) do
          let(:target) { Acceptance::Target.new(test_config[:target]) }

          let(:default_global_datastore) do
            {}
          end

          let(:test_environment) { allure_test_environment }

          let(:default_module_datastore) do
            {
              lhost: '127.0.0.1'
            }
          end

          # The shared session id that will be reused across the test run
          let(:session_id) do
            console.sendline "use #{target.session_module}"
            console.recvuntil(Acceptance::Console.prompt)

            # Set global options
            console.sendline target.setg_commands(default_global_datastore: default_global_datastore)
            console.recvuntil(Acceptance::Console.prompt)
            # TODO: update this when we add sessions
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

            session_id
          end

          before :each do |example|
            next unless example.respond_to?(:parameter)

            # Add the test environment metadata to the rspec example instance - so it appears in the final allure report UI
            test_environment.each do |key, value|
              example.parameter(key, value)
            end
          end

          after :all do
            driver.close_payloads
            console.reset
          end

          context 'when targeting a session', if: module_test[:targets].include?(:session) do
            it(
              "#{Acceptance::Session.current_platform}/#{runtime_name} session opens and passes the #{module_test[:name].inspect} tests"
            ) do
              with_test_harness(module_test) do |replication_commands|
                # Ensure we have a valid session id; We intentionally omit this from a `before(:each)` to ensure the allure attachments are generated if the session dies
                expect(session_id).to_not(be_nil, proc do
                  'There should be a session present'
                end)

                use_module = "use #{module_test[:name]}"
                run_command = module_test.key?(:action) ? module_test.fetch(:action) : 'run'
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
            it(
              "#{Acceptance::Session.current_platform}/#{runtime_name} rhost opens and passes the #{module_test[:name].inspect} tests"
            ) do
              with_test_harness(module_test) do |replication_commands|
                use_module = "use #{module_test[:name]}"
                run_command = module_test.key?(:action) ? module_test.fetch(:action) : 'run'
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
