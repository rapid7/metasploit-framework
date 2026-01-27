# -*- coding:binary -*-

require 'spec_helper'

RSpec.describe Msf::OptArray do
  let(:required_opt) { described_class.new('TestArray', [true, 'A test array', 'foo,bar']) }
  let(:not_required_opt) { described_class.new('TestArray', [false, 'A test array', 'foo,bar']) }
  let(:accepted_opt) { described_class.new('TestArray', [true, 'Extensions', 'stdapi,priv'], accepted: %w[stdapi priv incognito]) }
  let(:case_sensitive_opt) { described_class.new('TestArray', [true, 'Case sensitive', 'Foo,Bar'], accepted: %w[Foo Bar foo bar]) }
  let(:pipe_separator_opt) { described_class.new('TestArray', [true, 'Pipe separated', 'foo|bar'], separator: '|') }
  let(:no_unique_opt) { described_class.new('TestArray', [true, 'Allow duplicates', 'foo,bar'], unique: false) }

  it_behaves_like 'an option', [], [], 'array'

  describe '#type' do
    it 'returns array' do
      expect(required_opt.type).to eq('array')
    end
  end

  context 'initialization' do
    it 'accepts accepted parameter' do
      opt = described_class.new('Test', [true, 'desc', 'val'], accepted: %w[val1 val2])
      expect(opt.accepted).to eq(%w[val1 val2])
    end

    it 'accepts separator parameter' do
      opt = described_class.new('Test', [true, 'desc', 'val'], separator: '|')
      expect(opt.normalize('a|b|c')).to eq(%w[a b c])
    end

    it 'accepts strip_whitespace parameter' do
      opt = described_class.new('Test', [true, 'desc', 'val'], strip_whitespace: false)
      expect(opt.normalize(' a , b ')).to include(' a ')
    end

    it 'accepts unique parameter' do
      opt = described_class.new('Test', [true, 'desc', 'val'], unique: false)
      expect(opt.normalize('a,a,b')).to eq(%w[a a b])
    end
  end

  context 'validation when required' do
    it 'returns false for nil value' do
      expect(required_opt.valid?(nil)).to eq(false)
    end

    it 'returns false for empty string' do
      expect(required_opt.valid?('')).to eq(false)
    end

    it 'returns true for valid string' do
      expect(required_opt.valid?('foo,bar')).to eq(true)
    end

    it 'returns true for valid array' do
      expect(required_opt.valid?(%w[foo bar])).to eq(true)
    end

    it 'returns true for single value' do
      expect(required_opt.valid?('foo')).to eq(true)
    end
  end

  context 'validation when not required' do
    it 'returns true for nil value' do
      expect(not_required_opt.valid?(nil)).to eq(true)
    end

    it 'returns true for empty string' do
      expect(not_required_opt.valid?('', check_empty: false)).to eq(true)
    end

    it 'returns true for valid string' do
      expect(not_required_opt.valid?('foo,bar')).to eq(true)
    end
  end

  context 'validation with accepted values' do
    it 'returns true for valid values' do
      expect(accepted_opt.valid?('stdapi,priv')).to eq(true)
    end

    it 'returns true for single valid value' do
      expect(accepted_opt.valid?('stdapi')).to eq(true)
    end

    it 'returns false for invalid value' do
      expect(accepted_opt.valid?('stdapi,invalid')).to eq(false)
    end

    it 'returns false for all invalid values' do
      expect(accepted_opt.valid?('invalid1,invalid2')).to eq(false)
    end

    it 'returns true for case-insensitive match' do
      expect(accepted_opt.valid?('StdAPI,PRIV')).to eq(true)
    end
  end

  context 'normalization' do
    it 'normalizes comma-separated string to array' do
      expect(required_opt.normalize('foo,bar,baz')).to eq(%w[foo bar baz])
    end

    it 'normalizes space-separated string to array' do
      expect(required_opt.normalize('foo bar baz')).to eq(%w[foo bar baz])
    end

    it 'normalizes comma-space-separated string to array' do
      expect(required_opt.normalize('foo, bar, baz')).to eq(%w[foo bar baz])
    end

    it 'strips whitespace from members' do
      expect(required_opt.normalize('  foo  ,  bar  ')).to eq(%w[foo bar])
    end

    it 'removes empty members' do
      expect(required_opt.normalize('foo,,bar')).to eq(%w[foo bar])
    end

    it 'returns nil for nil value' do
      expect(required_opt.normalize(nil)).to eq(nil)
    end

    it 'handles array input' do
      expect(required_opt.normalize(%w[foo bar])).to eq(%w[foo bar])
    end
  end

  context 'normalization with unique' do
    it 'removes duplicates by default' do
      expect(required_opt.normalize('foo,bar,foo,baz')).to eq(%w[foo bar baz])
    end

    it 'preserves duplicates when unique is false' do
      expect(no_unique_opt.normalize('foo,bar,foo,baz')).to eq(%w[foo bar foo baz])
    end
  end

  context 'normalization with accepted values' do
    it 'normalizes case to match accepted values' do
      expect(accepted_opt.normalize('STDAPI,priv')).to eq(%w[stdapi priv])
    end

    it 'normalizes mixed case to match accepted values' do
      expect(accepted_opt.normalize('StdApi,PRIV,incognito')).to eq(%w[stdapi priv incognito])
    end

    it 'returns nil for invalid values' do
      expect(accepted_opt.normalize('stdapi,invalid')).to eq(nil)
    end

    it 'handles case-sensitive accepted values' do
      expect(case_sensitive_opt.normalize('Foo,bar')).to eq(%w[Foo bar])
    end
  end

  context 'normalization with custom separator' do
    it 'splits by pipe character' do
      expect(pipe_separator_opt.normalize('foo|bar|baz')).to eq(%w[foo bar baz])
    end

    it 'does not split by comma when using pipe separator' do
      expect(pipe_separator_opt.normalize('foo,bar|baz')).to eq(['foo,bar', 'baz'])
    end
  end

  context 'display_value' do
    it 'displays array as comma-separated string' do
      expect(required_opt.display_value(%w[foo bar baz])).to eq('foo, bar, baz')
    end

    it 'displays string value as comma-separated' do
      expect(required_opt.display_value('foo,bar,baz')).to eq('foo, bar, baz')
    end

    it 'handles single value' do
      expect(required_opt.display_value('foo')).to eq('foo')
    end
  end

  context 'description with accepted values' do
    it 'includes accepted values in description' do
      expect(accepted_opt.desc).to include('stdapi, priv, incognito')
    end

    it 'includes accepted label in description' do
      expect(accepted_opt.desc).to include('(Accepted:')
    end

    it 'does not include accepted when not defined' do
      expect(required_opt.desc).not_to include('(Accepted:')
    end
  end

  context 'case sensitivity' do
    it 'is case-insensitive when accepted values are unique ignoring case' do
      opt = described_class.new('Test', [true, 'desc', 'val'], accepted: %w[Foo Bar Baz])
      expect(opt.send(:case_sensitive?)).to eq(false)
    end

    it 'is case-sensitive when accepted values differ only by case' do
      opt = described_class.new('Test', [true, 'desc', 'val'], accepted: %w[Foo foo Bar bar])
      expect(opt.send(:case_sensitive?)).to eq(true)
    end
  end

  context 'edge cases' do
    it 'handles whitespace-only input' do
      expect(required_opt.normalize('   ')).to eq([])
    end

    it 'handles single comma' do
      expect(required_opt.normalize(',')).to eq([])
    end

    it 'handles multiple commas' do
      expect(required_opt.normalize(',,,')).to eq([])
    end

    it 'handles mixed separators' do
      expect(required_opt.normalize('foo, bar baz,qux')).to eq(%w[foo bar baz qux])
    end
  end

  context 'real-world example: Meterpreter extensions' do
    let(:extensions_opt) do
      described_class.new(
        'AutoLoadExtensions',
        [true, 'Extensions to automatically load', 'stdapi, priv'],
        accepted: %w[stdapi priv incognito kiwi python]
      )
    end

    it 'handles comma-separated extensions' do
      expect(extensions_opt.valid?('stdapi,priv')).to eq(true)
      expect(extensions_opt.normalize('stdapi,priv')).to eq(%w[stdapi priv])
    end

    it 'handles space-separated extensions' do
      expect(extensions_opt.valid?('stdapi priv')).to eq(true)
      expect(extensions_opt.normalize('stdapi priv')).to eq(%w[stdapi priv])
    end

    it 'handles comma-space-separated extensions' do
      expect(extensions_opt.valid?('stdapi, priv, incognito')).to eq(true)
      expect(extensions_opt.normalize('stdapi, priv, incognito')).to eq(%w[stdapi priv incognito])
    end

    it 'normalizes case for extensions' do
      expect(extensions_opt.normalize('STDAPI,Priv')).to eq(%w[stdapi priv])
    end

    it 'rejects invalid extensions' do
      expect(extensions_opt.valid?('stdapi,invalid_ext')).to eq(false)
    end

    it 'removes duplicate extensions' do
      expect(extensions_opt.normalize('stdapi,priv,stdapi')).to eq(%w[stdapi priv])
    end
  end
end
