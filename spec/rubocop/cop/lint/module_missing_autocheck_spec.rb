# frozen_string_literal: true

require 'spec_helper'
require 'rubocop/cop/lint/module_missing_autocheck'

RSpec.describe RuboCop::Cop::Lint::ModuleMissingAutocheck do
  subject(:cop) { described_class.new(config) }
  let(:empty_rubocop_config) { {} }
  let(:config) { RuboCop::Config.new(empty_rubocop_config) }

  it 'flags module with def check but no prepend AutoCheck' do
    expect_offense(<<~RUBY)
      class MetasploitModule < Msf::Exploit::Remote
        include Msf::Exploit::Remote::HttpClient

        def initialize(info = {})
          super(update_info(info, 'Name' => 'Test'))
        end

        def check
        ^^^^^^^^^ Module has a check method but does not prepend Msf::Exploit::Remote::AutoCheck. [...]
          CheckCode::Safe('Not vulnerable')
        end

        def exploit
        end
      end
    RUBY
  end

  it 'does not flag module with def check AND prepend AutoCheck' do
    expect_no_offenses(<<~RUBY)
      class MetasploitModule < Msf::Exploit::Remote
        include Msf::Exploit::Remote::HttpClient
        prepend Msf::Exploit::Remote::AutoCheck

        def initialize(info = {})
          super(update_info(info, 'Name' => 'Test'))
        end

        def check
          CheckCode::Safe('Not vulnerable')
        end

        def exploit
        end
      end
    RUBY
  end

  it 'does not flag module without a check method' do
    expect_no_offenses(<<~RUBY)
      class MetasploitModule < Msf::Exploit::Remote
        include Msf::Exploit::Remote::HttpClient

        def initialize(info = {})
          super(update_info(info, 'Name' => 'Test'))
        end

        def exploit
        end
      end
    RUBY
  end

  it 'does not flag when AutoCheck is prepended with full const path' do
    expect_no_offenses(<<~RUBY)
      class MetasploitModule < Msf::Exploit::Remote
        include Msf::Exploit::Remote::HttpClient
        prepend Msf::Exploit::Remote::AutoCheck

        def check
          CheckCode::Appears('Version looks vulnerable')
        end

        def exploit
        end
      end
    RUBY
  end
end
