# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Msf::Module::VersionRange do
  describe '.valid_version_value?' do
    [
      { value: nil,     expected: false },
      { value: 'nil',   expected: false },
      { value: '',      expected: false },
      { value: 0,       expected: true  },
      { value: '0',     expected: true  },
      { value: false,   expected: false },
      { value: true,    expected: false },
      { value: {},      expected: false },
      { value: [],      expected: false },
      { value: [{}],    expected: false },
      { value: '0.0.1', expected: true  },
      { value: '1.0.0', expected: true  },
      { value: '1.0.0.0', expected: true },
    ].each do |test_case|
      context "when provided with #{test_case[:value].inspect}" do
        it "returns #{test_case[:expected]}" do
          expect(described_class.valid_version_value?(test_case[:value])).to eq(test_case[:expected])
        end
      end
    end
  end

  describe '#initialize' do
    context 'when neither min nor max is provided' do
      it 'raises an error' do
        expect { described_class.new }.to raise_error(RuntimeError, /Improper argument/)
      end
    end

    context 'when min is an invalid string' do
      it 'raises an error' do
        expect { described_class.new(min: 'nil', max: '1.0.0') }.to raise_error(RuntimeError, /Improper argument/)
      end
    end

    context 'when max is an invalid string' do
      it 'raises an error' do
        expect { described_class.new(min: '1.0.0', max: 'nil') }.to raise_error(RuntimeError, /Improper argument/)
      end
    end

    context 'when both min and max are valid' do
      it 'does not raise' do
        expect { described_class.new(min: '1.0.0', max: '2.0.0') }.not_to raise_error
      end
    end

    context 'when max is nil (unbounded upper range)' do
      it 'does not raise' do
        expect { described_class.new(min: '1.0.0') }.not_to raise_error
      end

      it 'stores nil max' do
        range = described_class.new(min: '1.0.0')
        expect(range.max).to be_nil
      end
    end

    context 'when min is nil (unbounded lower range)' do
      it 'does not raise' do
        expect { described_class.new(max: '5.0.0') }.not_to raise_error
      end

      it 'stores nil min' do
        range = described_class.new(max: '5.0.0')
        expect(range.min).to be_nil
      end
    end
  end

  describe '#contains?' do
    [
      # bounded range
      { min: '0.0.0', max: '1.0.0', value: nil,     expected: nil   },
      { min: '0.0.0', max: '1.0.0', value: 'nil',   expected: nil   },
      { min: '0.0.0', max: '1.0.0', value: '1.0.0', expected: true  },
      { min: '0.0.0', max: '1.0.0', value: '0.5.0', expected: true  },
      { min: '0.0.0', max: '1.0.0', value: '1.0.1', expected: false },
      { min: '0.0.0', max: '1.0.0', value: 0,       expected: true  },
      { min: '0.0.0', max: '1.0.0', value: 1,       expected: true  },
      { min: '0.0.0', max: '1.0.0', value: 5,       expected: false },
      # unbounded range (no max)
      { min: '1.0.0', max: nil, value: '0.9.0',   expected: false },
      { min: '1.0.0', max: nil, value: '1.0.0',   expected: true  },
      { min: '1.0.0', max: nil, value: '99.0.0',  expected: true  },
      # unbounded range (no min)
      { min: nil, max: '5.0.0', value: '0.0.1',   expected: true  },
      { min: nil, max: '5.0.0', value: '4.9.9',   expected: true  },
      { min: nil, max: '5.0.0', value: '5.0.0',   expected: true  },
      { min: nil, max: '5.0.0', value: '5.0.1',   expected: false },
      { min: nil, max: '5.0.0', value: '99.0.0',  expected: false },
      { min: nil, max: '5.0.0', value: nil,        expected: nil   },
      { min: nil, max: '5.0.0', value: 'nil',      expected: nil   },
      { min: nil, max: '5.0.0', value: 0,          expected: true  },
      { min: nil, max: '5.0.0', value: 5,          expected: true  },
      { min: nil, max: '5.0.0', value: 6,          expected: false },
      # boundary conditions
      { min: '2.5',   max: '2.7', value: '2.4',   expected: false },
      { min: '2.5',   max: '2.7', value: '2.5',   expected: true  },
      { min: '2.5',   max: '2.7', value: '2.6',   expected: true  },
      { min: '2.5',   max: '2.7', value: '2.7',   expected: true  },
      { min: '2.5',   max: '2.7', value: '3.0',   expected: false },
    ].each do |test_case|
      context "with range #{test_case[:min] || '(infinite)'}..#{test_case[:max] || '(infinite)'}" do
        it "returns #{test_case[:expected].inspect} for value #{test_case[:value].inspect}" do
          subject = described_class.new(min: test_case[:min], max: test_case[:max])
          expect(subject.contains?(test_case[:value])).to eq(test_case[:expected])
        end
      end
    end
  end
end
