# frozen_string_literal: true

require 'spec_helper'
require 'rubocop/cop/lint/module_default_payload'

RSpec.describe RuboCop::Cop::Lint::ModuleDefaultPayload do
  subject(:cop) { described_class.new(config) }
  let(:empty_rubocop_config) { {} }
  let(:config) { RuboCop::Config.new(empty_rubocop_config) }

  it 'flags DefaultOptions containing PAYLOAD key' do
    expect_offense(<<~RUBY)
      class MetasploitModule < Msf::Exploit::Remote
        def initialize(info = {})
          super(
            update_info(
              info,
              'Name' => 'Test Module',
              'DefaultOptions' => {
                'PAYLOAD' => 'cmd/unix/reverse_bash'
                ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Do not hardcode a default PAYLOAD in DefaultOptions [...]
              }
            )
          )
        end
      end
    RUBY
  end

  it 'does not flag DefaultOptions without PAYLOAD key' do
    expect_no_offenses(<<~RUBY)
      class MetasploitModule < Msf::Exploit::Remote
        def initialize(info = {})
          super(
            update_info(
              info,
              'Name' => 'Test Module',
              'DefaultOptions' => {
                'SSL' => true,
                'WfsDelay' => 5
              }
            )
          )
        end
      end
    RUBY
  end

  it 'does not flag modules without DefaultOptions' do
    expect_no_offenses(<<~RUBY)
      class MetasploitModule < Msf::Exploit::Remote
        def initialize(info = {})
          super(
            update_info(
              info,
              'Name' => 'Test Module',
              'Author' => ['Test']
            )
          )
        end
      end
    RUBY
  end

  it 'does not flag PAYLOAD string used outside DefaultOptions context' do
    expect_no_offenses(<<~RUBY)
      class MetasploitModule < Msf::Exploit::Remote
        def initialize(info = {})
          super(
            update_info(
              info,
              'Name' => 'Test Module',
              'Notes' => {
                'PAYLOAD' => 'this is not DefaultOptions'
              }
            )
          )
        end
      end
    RUBY
  end
end
