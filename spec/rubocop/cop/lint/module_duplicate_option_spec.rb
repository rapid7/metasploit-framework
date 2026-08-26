# frozen_string_literal: true

require 'spec_helper'
require 'rubocop/cop/lint/module_duplicate_option'

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

  it 'does not flag an inherited option registered with an option class' do
    expect_no_offenses(<<~RUBY)
      class MetasploitModule < Msf::Auxiliary
        include Msf::Exploit::Remote::Tcp

        def initialize(info = {})
          super
          register_options([OptPort.new('RPORT', [true, 'The target port', 4840])])
        end
      end
    RUBY
  end

  it 'does not flag an option class already registered by the HTTP client mixin' do
    expect_no_offenses(<<~RUBY)
      class MetasploitModule < Msf::Auxiliary
        include Msf::Exploit::Remote::HttpClient

        def initialize(info = {})
          super
          register_options([OptBool.new('SSL', [false, 'Negotiate SSL/TLS for outgoing connections', true])])
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

  it 'does not flag an option class already registered by the scanner mixin' do
    expect_no_offenses(<<~RUBY)
      class MetasploitModule < Msf::Auxiliary
        include Msf::Auxiliary::Scanner

        def initialize(info = {})
          super
          register_options([OptInt.new('THREADS', [true, 'The number of concurrent threads (max one per host)', 25])])
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

  it 'does not flag an inherited option when its required value also changes' do
    expect_no_offenses(<<~RUBY)
      class MetasploitModule < Msf::Auxiliary
        include Msf::Exploit::Remote::Tcp

        def initialize(info = {})
          super
          register_options([OptPort.new('RPORT', [false, 'The target port', 4840])])
        end
      end
    RUBY
  end

  it 'does not flag an inherited option when its type also changes' do
    expect_no_offenses(<<~RUBY)
      class MetasploitModule < Msf::Auxiliary
        include Msf::Exploit::Remote::Tcp

        def initialize(info = {})
          super
          register_options([OptString.new('RPORT', [true, 'The target port', '4840'])])
        end
      end
    RUBY
  end

  it 'does not flag an identical inherited option' do
    expect_no_offenses(<<~RUBY)
      class MetasploitModule < Msf::Auxiliary
        include Msf::Exploit::Remote::HttpClient

        def initialize(info = {})
          super
          register_options([Opt::RPORT(80)])
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
          register_options([Opt::RPORT(4840, false)])
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
end
