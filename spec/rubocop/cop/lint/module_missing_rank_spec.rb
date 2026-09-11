# frozen_string_literal: true

require 'spec_helper'
require 'rubocop/cop/lint/module_missing_rank'

RSpec.describe RuboCop::Cop::Lint::ModuleMissingRank do
  subject(:cop) { described_class.new(config) }
  let(:empty_rubocop_config) { {} }
  let(:config) { RuboCop::Config.new(empty_rubocop_config) }

  msg = 'Module does not declare an explicit Rank (it will silently default to NormalRanking). ' \
        'Add `Rank = <value>` using a value from lib/msf/core/constants.rb (ManualRanking through ExcellentRanking).'

  # _investigate's return shape is RuboCop-version-dependent: some versions return
  # the offenses array directly, others return a report object (or a [report, offenses]
  # pair) exposing #offenses. Normalize to the offenses array so assertions are stable
  # across versions.
  def offenses_from(result)
    return result.offenses if result.respond_to?(:offenses)
    return result.last.offenses if result.is_a?(Array) && result.last.respond_to?(:offenses)

    result
  end

  it 'flags a MetasploitModule with no Rank declaration' do
    source = <<~RUBY
      class MetasploitModule < Msf::Exploit::Remote
        def initialize(info = {})
          super(update_info(info, 'Name' => 'Test'))
        end

        def exploit
        end
      end
    RUBY
    offenses = offenses_from(_investigate(cop, parse_source(source, 'test.rb')))
    expect(offenses.size).to eq(1)
    expect(offenses.first.message).to eq(msg)
  end

  it 'does not flag a module that declares a Rank' do
    expect_no_offenses(<<~RUBY)
      class MetasploitModule < Msf::Exploit::Remote
        Rank = GreatRanking

        def initialize(info = {})
          super(update_info(info, 'Name' => 'Test'))
        end

        def exploit
        end
      end
    RUBY
  end

  it 'accepts any valid ranking constant' do
    %w[ManualRanking LowRanking AverageRanking NormalRanking GoodRanking GreatRanking ExcellentRanking].each do |rank|
      expect_no_offenses(<<~RUBY)
        class MetasploitModule < Msf::Exploit::Remote
          Rank = #{rank}

          def initialize(info = {})
            super(update_info(info, 'Name' => 'Test'))
          end

          def exploit
          end
        end
      RUBY
    end
  end

  it 'recognizes a Rank declared alongside other constants' do
    expect_no_offenses(<<~RUBY)
      class MetasploitModule < Msf::Exploit::Remote
        SOME_CONST = 1
        Rank = NormalRanking

        def exploit
        end
      end
    RUBY
  end
end
