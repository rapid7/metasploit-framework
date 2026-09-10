# frozen_string_literal: true

require 'spec_helper'
require 'rubocop/cop/lint/module_http_fingerprint'

RSpec.describe RuboCop::Cop::Lint::ModuleHttpFingerprint do
  subject(:cop) { described_class.new(config) }
  let(:empty_rubocop_config) { {} }
  let(:config) { RuboCop::Config.new(empty_rubocop_config) }

  it 'flags HttpFingerprint constant assignment' do
    expect_offense(<<~RUBY)
      class MetasploitModule < Msf::Exploit::Remote
        HttpFingerprint = { :pattern => [/Apache/] }
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ HttpFingerprint is a legacy passive fingerprinting mechanism. [...]
      end
    RUBY
  end

  it 'does not flag other constant assignments' do
    expect_no_offenses(<<~RUBY)
      class MetasploitModule < Msf::Exploit::Remote
        Rank = ExcellentRanking
      end
    RUBY
  end

  it 'does not flag local variable named http_fingerprint' do
    expect_no_offenses(<<~RUBY)
      class MetasploitModule < Msf::Exploit::Remote
        def check
          http_fingerprint = {}
        end
      end
    RUBY
  end

  it 'flags HttpFingerprint with different value types' do
    expect_offense(<<~RUBY)
      class MetasploitModule < Msf::Exploit::Remote
        HttpFingerprint = { :uri => '/index.html', :pattern => [] }
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ HttpFingerprint is a legacy passive fingerprinting mechanism. [...]
      end
    RUBY
  end
end
