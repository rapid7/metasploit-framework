# frozen_string_literal: true

require 'rubocop/cop/lint/check_code_missing_reason'
require 'rubocop/rspec/support'

RSpec.describe RuboCop::Cop::Lint::CheckCodeMissingReason, :config do
  subject(:cop) { described_class.new(config) }

  let(:config) { RuboCop::Config.new }

  context 'when inside def check' do
    context 'with a bare constant (no call)' do
      it 'registers an offense for CheckCode::Safe' do
        expect_offense(<<~RUBY)
          def check
            CheckCode::Safe
            ^^^^^^^^^^^^^^^ Lint/CheckCodeMissingReason: Provide a human-readable reason string when returning a CheckCode, e.g. `CheckCode::Safe('The target is not vulnerable because ...')`
          end
        RUBY
      end

      it 'registers an offense for CheckCode::Vulnerable' do
        expect_offense(<<~RUBY)
          def check
            CheckCode::Vulnerable
            ^^^^^^^^^^^^^^^^^^^^^ Lint/CheckCodeMissingReason: Provide a human-readable reason string when returning a CheckCode, e.g. `CheckCode::Vulnerable('The target is not vulnerable because ...')`
          end
        RUBY
      end

      it 'registers an offense for CheckCode::Appears' do
        expect_offense(<<~RUBY)
          def check
            CheckCode::Appears
            ^^^^^^^^^^^^^^^^^^ Lint/CheckCodeMissingReason: Provide a human-readable reason string when returning a CheckCode, e.g. `CheckCode::Appears('The target is not vulnerable because ...')`
          end
        RUBY
      end

      it 'registers an offense for CheckCode::Unknown' do
        expect_offense(<<~RUBY)
          def check
            CheckCode::Unknown
            ^^^^^^^^^^^^^^^^^^ Lint/CheckCodeMissingReason: Provide a human-readable reason string when returning a CheckCode, e.g. `CheckCode::Unknown('The target is not vulnerable because ...')`
          end
        RUBY
      end

      it 'registers an offense for CheckCode::Detected' do
        expect_offense(<<~RUBY)
          def check
            CheckCode::Detected
            ^^^^^^^^^^^^^^^^^^^ Lint/CheckCodeMissingReason: Provide a human-readable reason string when returning a CheckCode, e.g. `CheckCode::Detected('The target is not vulnerable because ...')`
          end
        RUBY
      end

      it 'registers an offense for CheckCode::Unsupported' do
        expect_offense(<<~RUBY)
          def check
            CheckCode::Unsupported
            ^^^^^^^^^^^^^^^^^^^^^^ Lint/CheckCodeMissingReason: Provide a human-readable reason string when returning a CheckCode, e.g. `CheckCode::Unsupported('The target is not vulnerable because ...')`
          end
        RUBY
      end

      it 'registers an offense for Exploit::CheckCode::Safe' do
        expect_offense(<<~RUBY)
          def check
            Exploit::CheckCode::Safe
            ^^^^^^^^^^^^^^^^^^^^^^^^ Lint/CheckCodeMissingReason: Provide a human-readable reason string when returning a CheckCode, e.g. `Exploit::CheckCode::Safe('The target is not vulnerable because ...')`
          end
        RUBY
      end

      it 'registers an offense for Msf::Exploit::CheckCode::Appears' do
        expect_offense(<<~RUBY)
          def check
            Msf::Exploit::CheckCode::Appears
            ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Lint/CheckCodeMissingReason: Provide a human-readable reason string when returning a CheckCode, e.g. `Msf::Exploit::CheckCode::Appears('The target is not vulnerable because ...')`
          end
        RUBY
      end
    end

    context 'with an empty call (no arguments)' do
      it 'registers an offense for CheckCode::Safe()' do
        expect_offense(<<~RUBY)
          def check
            CheckCode::Safe()
            ^^^^^^^^^^^^^^^^^ Lint/CheckCodeMissingReason: Provide a human-readable reason string when returning a CheckCode, e.g. `CheckCode::Safe('The target is not vulnerable because ...')`
          end
        RUBY
      end

      it 'registers an offense for Exploit::CheckCode::Unknown()' do
        expect_offense(<<~RUBY)
          def check
            Exploit::CheckCode::Unknown()
            ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Lint/CheckCodeMissingReason: Provide a human-readable reason string when returning a CheckCode, e.g. `Exploit::CheckCode::Unknown('The target is not vulnerable because ...')`
          end
        RUBY
      end
    end

    context 'with only keyword arguments (no positional reason string)' do
      it 'registers an offense for CheckCode::Vulnerable(details: {...})' do
        expect_offense(<<~RUBY)
          def check
            CheckCode::Vulnerable(details: { version: '1.0' })
            ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Lint/CheckCodeMissingReason: Provide a human-readable reason string when returning a CheckCode, e.g. `CheckCode::Vulnerable('The target is not vulnerable because ...')`
          end
        RUBY
      end

      it 'registers an offense for Exploit::CheckCode::Vulnerable(details: {...}, vuln: {})' do
        expect_offense(<<~RUBY)
          def check
            Exploit::CheckCode::Vulnerable(details: { version: '1.0' }, vuln: {})
            ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Lint/CheckCodeMissingReason: Provide a human-readable reason string when returning a CheckCode, e.g. `Exploit::CheckCode::Vulnerable('The target is not vulnerable because ...')`
          end
        RUBY
      end
    end

    context 'when the bare constant is used as a comparator inside def check' do
      it 'does not register an offense for == comparison against a stored checkcode' do
        expect_no_offenses(<<~RUBY)
          def check
            checkcode = check_plugin_version_from_readme('some-plugin', '1.0')
            if checkcode == Msf::Exploit::CheckCode::Safe
              return Msf::Exploit::CheckCode::Safe('Plugin version is not vulnerable')
            end
            checkcode
          end
        RUBY
      end

      it 'does not register an offense for eql? comparison inside def check' do
        expect_no_offenses(<<~RUBY)
          def check
            result = get_check_result
            return CheckCode::Unknown('Could not determine status') if result.eql? CheckCode::Safe
            result
          end
        RUBY
      end
    end

    context 'with a reason argument' do
      it 'does not register an offense for a plain string' do
        expect_no_offenses(<<~RUBY)
          def check
            CheckCode::Safe('The target is not running the vulnerable service')
          end
        RUBY
      end

      it 'does not register an offense for an interpolated string' do
        expect_no_offenses(<<~RUBY)
          def check
            CheckCode::Appears("Version \#{version} appears vulnerable")
          end
        RUBY
      end

      it 'does not register an offense for a string with a details kwarg' do
        expect_no_offenses(<<~RUBY)
          def check
            CheckCode::Vulnerable('Confirmed vulnerable', details: { version: '1.0' })
          end
        RUBY
      end

      it 'does not register an offense for an exception object' do
        expect_no_offenses(<<~RUBY)
          def check
            CheckCode::Safe(e)
          end
        RUBY
      end

      it 'does not register an offense for a variable' do
        expect_no_offenses(<<~RUBY)
          def check
            CheckCode::Unknown(reason)
          end
        RUBY
      end
    end
  end

  context 'when outside def check' do
    it 'does not register an offense for a bare constant in a comparison' do
      expect_no_offenses(<<~RUBY)
        def exploit
          fail_with(Failure::Unknown, 'Not vulnerable') unless check == CheckCode::Safe
        end
      RUBY
    end

    it 'does not register an offense for a bare constant with eql?' do
      expect_no_offenses(<<~RUBY)
        def exploit
          fail_with(Failure::Unknown, 'msg') if check.eql? Exploit::CheckCode::Vulnerable
        end
      RUBY
    end

    it 'does not register an offense for bare constants in a case/when branch' do
      expect_no_offenses(<<~RUBY)
        def exploit
          case checkcode
          when Exploit::CheckCode::Vulnerable, Exploit::CheckCode::Appears
            print_good(checkcode.message)
          end
        end
      RUBY
    end

    it 'does not register an offense for calls in a case/when branch' do
      expect_no_offenses(<<~RUBY)
        def exploit
          case checkcode
          when Exploit::CheckCode::Vulnerable('msg'), Exploit::CheckCode::Appears
            print_good(checkcode.message)
          end
        end
      RUBY
    end

    it 'does not register an offense for bare constants in an array' do
      expect_no_offenses(<<~RUBY)
        def run
          [Msf::Exploit::CheckCode::Vulnerable, Msf::Exploit::CheckCode::Appears].include?(result)
        end
      RUBY
    end

    it 'does not register an offense for a bare constant at the top level' do
      expect_no_offenses(<<~RUBY)
        CheckCode::Safe
      RUBY
    end
  end
end
