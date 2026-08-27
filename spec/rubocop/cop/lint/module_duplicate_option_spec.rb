# frozen_string_literal: true

require 'spec_helper'
require 'rubocop/cop/lint/module_duplicate_option'

# rubocop:disable Metrics/BlockLength
RSpec.describe RuboCop::Cop::Lint::ModuleDuplicateOption do
  subject(:cop) { described_class.new(config) }

  let(:config) { RuboCop::Config.new }

  it 'flags an RPORT option already registered by the TCP mixin' do
    expect_offense(<<~RUBY)
      class MetasploitModule < Msf::Auxiliary
        include Msf::Exploit::Remote::Tcp

        def initialize(info = {})
          super
          register_options([Opt::RPORT(4840)])
                            ^^^^^^^^^^^^^^^^ Lint/ModuleDuplicateOption: Do not register the pre-existing RPORT option again; set its value in DefaultOptions instead.
        end
      end
    RUBY
  end

  it 'flags an inherited option registered with the same description' do
    expect_offense(<<~RUBY)
      class MetasploitModule < Msf::Auxiliary
        include Msf::Exploit::Remote::Tcp

        def initialize(info = {})
          super
          register_options([OptPort.new('RPORT', [true, 'The target port', 4840])])
                            ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Lint/ModuleDuplicateOption: Do not register the pre-existing RPORT option again; set its value in DefaultOptions instead.
        end
      end
    RUBY
  end

  it 'flags an option class with the inherited description' do
    expect_offense(<<~RUBY)
      class MetasploitModule < Msf::Auxiliary
        include Msf::Exploit::Remote::HttpClient

        def initialize(info = {})
          super
          register_options([OptBool.new('SSL', [false, 'Negotiate SSL/TLS for outgoing connections', true])])
                            ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Lint/ModuleDuplicateOption: Do not register the pre-existing SSL option again; set its value in DefaultOptions instead.
        end
      end
    RUBY
  end

  it 'flags an option already registered by the UDP mixin' do
    expect_offense(<<~RUBY)
      class MetasploitModule < Msf::Auxiliary
        include Msf::Exploit::Remote::Udp

        def initialize(info = {})
          super
          register_options([Opt::RPORT(161)])
                            ^^^^^^^^^^^^^^^ Lint/ModuleDuplicateOption: Do not register the pre-existing RPORT option again; set its value in DefaultOptions instead.
        end
      end
    RUBY
  end

  it 'flags a computed RPORT default used by a real module' do
    expect_offense(<<~RUBY)
      class MetasploitModule < Msf::Exploit::Remote
        include Msf::Exploit::Remote::Tcp

        def initialize(info = {})
          super
          register_options([Opt::RPORT(Rex::Proto::PJL::DEFAULT_PORT)])
                            ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Lint/ModuleDuplicateOption: Do not register the pre-existing RPORT option again; set its value in DefaultOptions instead.
        end
      end
    RUBY
  end

  it 'flags an RHOST default used by real modules' do
    expect_offense(<<~RUBY)
      class MetasploitModule < Msf::Auxiliary
        include Msf::Exploit::Remote::HttpClient

        def initialize(info = {})
          super
          register_options([Opt::RHOST('192.168.100.1')])
                            ^^^^^^^^^^^^^^^^^^^^^^^^^^^ Lint/ModuleDuplicateOption: Do not register the pre-existing RHOST option again; set its value in DefaultOptions instead.
        end
      end
    RUBY
  end

  it 'flags an option class already registered by the scanner mixin' do
    expect_offense(<<~RUBY)
      class MetasploitModule < Msf::Auxiliary
        include Msf::Auxiliary::Scanner

        def initialize(info = {})
          super
          register_options([OptInt.new('THREADS', [true, 'The number of concurrent threads (max one per host)', 25])])
                            ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Lint/ModuleDuplicateOption: Do not register the pre-existing THREADS option again; set its value in DefaultOptions instead.
        end
      end
    RUBY
  end

  it 'does not flag an inherited option when its description also changes' do
    expect_no_offenses(<<~RUBY)
      class MetasploitModule < Msf::Auxiliary
        include Msf::Exploit::Remote::HttpClient

        def initialize(info = {})
          super
          register_options([OptBool.new('SSL', [false, 'Use SSL', true])])
        end
      end
    RUBY
  end

  it 'flags an inherited option when its required value changes but its description does not' do
    expect_offense(<<~RUBY)
      class MetasploitModule < Msf::Auxiliary
        include Msf::Exploit::Remote::Tcp

        def initialize(info = {})
          super
          register_options([OptPort.new('RPORT', [false, 'The target port', 4840])])
                            ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Lint/ModuleDuplicateOption: Do not register the pre-existing RPORT option again; set its value in DefaultOptions instead.
        end
      end
    RUBY
  end

  it 'flags an inherited option when its type and description change without autocorrecting it' do
    expect_offense(<<~RUBY)
      class MetasploitModule < Msf::Auxiliary
        include Msf::Exploit::Remote::Tcp

        def initialize(info = {})
          super
          register_options([OptString.new('RPORT', [true, 'The application port', '4840'])])
                            ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Lint/ModuleDuplicateOption: Do not change the type of the pre-existing RPORT option from OptPort to OptString.
        end
      end
    RUBY

    expect_no_corrections
  end

  it 'flags an identical inherited option' do
    expect_offense(<<~RUBY)
      class MetasploitModule < Msf::Auxiliary
        include Msf::Exploit::Remote::HttpClient

        def initialize(info = {})
          super
          register_options([Opt::RPORT(80)])
                            ^^^^^^^^^^^^^^ Lint/ModuleDuplicateOption: Do not register the pre-existing RPORT option again; set its value in DefaultOptions instead.
        end
      end
    RUBY
  end

  it 'does not flag an Opt helper call that changes requiredness too' do
    expect_no_offenses(<<~RUBY)
      class MetasploitModule < Msf::Auxiliary
        include Msf::Exploit::Remote::Tcp

        def initialize(info = {})
          super
          register_options([Opt::RPORT(4840, false, 'The application port')])
        end
      end
    RUBY
  end

  it 'does not flag new options' do
    expect_no_offenses(<<~RUBY)
      class MetasploitModule < Msf::Auxiliary
        include Msf::Exploit::Remote::Tcp

        def initialize(info = {})
          super
          register_options([OptString.new('ENDPOINT', [true, 'Endpoint', '/'])])
        end
      end
    RUBY
  end

  it 'does not flag RPORT when the TCP mixin is not included' do
    expect_no_offenses(<<~RUBY)
      class MetasploitModule < Msf::Auxiliary
        def initialize(info = {})
          super
          register_options([Opt::RPORT(4840)])
        end
      end
    RUBY
  end

  it 'allows an option to be deliberately deregistered and replaced' do
    expect_no_offenses(<<~RUBY)
      class MetasploitModule < Msf::Auxiliary
        include Msf::Exploit::Remote::Tcp

        def initialize(info = {})
          super
          deregister_options('RPORT')
          register_options([OptPort.new('RPORT', [true, 'A replacement port'])])
        end
      end
    RUBY
  end

  it 'accepts DefaultOptions as the way to change the inherited default' do
    expect_no_offenses(<<~RUBY)
      class MetasploitModule < Msf::Auxiliary
        include Msf::Exploit::Remote::Tcp

        def initialize(info = {})
          super(update_info(info, 'DefaultOptions' => { 'RPORT' => 4840 }))
        end
      end
    RUBY
  end

  it 'moves a changed default to DefaultOptions' do
    expect_offense(<<~RUBY)
      class MetasploitModule < Msf::Auxiliary
        include Msf::Exploit::Remote::Tcp

        def initialize(info = {})
          super(update_info(
            info,
            'Name' => 'Example'
          ))
          register_options([Opt::RPORT(4840)])
                            ^^^^^^^^^^^^^^^^ Lint/ModuleDuplicateOption: Do not register the pre-existing RPORT option again; set its value in DefaultOptions instead.
        end
      end
    RUBY

    expect_correction(<<~RUBY)
      class MetasploitModule < Msf::Auxiliary
        include Msf::Exploit::Remote::Tcp

        def initialize(info = {})
          super(update_info(
            info,
            'DefaultOptions' => {
              'RPORT' => 4840
            },
            'Name' => 'Example'
          ))
        end
      end
    RUBY
  end

  it 'removes an identical option without adding a default' do
    expect_offense(<<~RUBY)
      class MetasploitModule < Msf::Auxiliary
        include Msf::Exploit::Remote::HttpClient

        def initialize(info = {})
          super(update_info(info, 'Name' => 'Example'))
          register_options([OptString.new('VHOST', [false, 'HTTP server virtual host'])])
                            ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Lint/ModuleDuplicateOption: Do not register the pre-existing VHOST option again; set its value in DefaultOptions instead.
        end
      end
    RUBY

    expect_correction(<<~RUBY)
      class MetasploitModule < Msf::Auxiliary
        include Msf::Exploit::Remote::HttpClient

        def initialize(info = {})
          super(update_info(info, 'Name' => 'Example'))
        end
      end
    RUBY
  end

  it 'merges multiple changed defaults into existing DefaultOptions' do
    expect_offense(<<~RUBY)
      class MetasploitModule < Msf::Auxiliary
        include Msf::Exploit::Remote::Tcp

        def initialize(info = {})
          super(update_info(
            info,
            'DefaultOptions' => {
              'RPORT' => 1234,
              'VERBOSE' => true
            }
          ))
          register_options([
            Opt::RPORT(8080),
            ^^^^^^^^^^^^^^^^ Lint/ModuleDuplicateOption: Do not register the pre-existing RPORT option again; set its value in DefaultOptions instead.
            Opt::RHOST('127.0.0.1')
            ^^^^^^^^^^^^^^^^^^^^^^^ Lint/ModuleDuplicateOption: Do not register the pre-existing RHOST option again; set its value in DefaultOptions instead.
          ])
        end
      end
    RUBY

    expect_correction(<<~RUBY)
      class MetasploitModule < Msf::Auxiliary
        include Msf::Exploit::Remote::Tcp

        def initialize(info = {})
          super(update_info(
            info,
            'DefaultOptions' => {
              'RPORT' => 8080,
              'VERBOSE' => true,
              'RHOST' => '127.0.0.1'
            }
          ))
        end
      end
    RUBY
  end

  it 'keeps unrelated options in the registration array' do
    expect_offense(<<~RUBY)
      class MetasploitModule < Msf::Auxiliary
        include Msf::Exploit::Remote::Tcp

        def initialize(info = {})
          super(update_info(
            info,
            'Name' => 'Example'
          ))
          register_options([
            Opt::RPORT(4840),
            ^^^^^^^^^^^^^^^^ Lint/ModuleDuplicateOption: Do not register the pre-existing RPORT option again; set its value in DefaultOptions instead.
            OptString.new('PATH', [true, 'A path'])
          ])
        end
      end
    RUBY

    expect_correction(<<~RUBY)
      class MetasploitModule < Msf::Auxiliary
        include Msf::Exploit::Remote::Tcp

        def initialize(info = {})
          super(update_info(
            info,
            'DefaultOptions' => {
              'RPORT' => 4840
            },
            'Name' => 'Example'
          ))
          register_options([
            OptString.new('PATH', [true, 'A path'])
          ])
        end
      end
    RUBY
  end

  it 'merges a default into legacy super metadata' do
    expect_offense(<<~RUBY)
      class MetasploitModule < Msf::Auxiliary
        include Msf::Exploit::Remote::HttpClient

        def initialize
          super(
            'Name' => 'Example',
            'DefaultOptions' => { 'SSL' => true }
          )
          register_options([Opt::RPORT(443)]) # HTTPS port
                            ^^^^^^^^^^^^^^^ Lint/ModuleDuplicateOption: Do not register the pre-existing RPORT option again; set its value in DefaultOptions instead.
        end
      end
    RUBY

    expect_correction(<<~RUBY)
      class MetasploitModule < Msf::Auxiliary
        include Msf::Exploit::Remote::HttpClient

        def initialize
          super(
            'Name' => 'Example',
            # HTTPS port
            'DefaultOptions' => { 'SSL' => true, 'RPORT' => 443 }
          )
        end
      end
    RUBY
  end
end
# rubocop:enable Metrics/BlockLength
