# -*- coding: binary -*-

require 'spec_helper'

RSpec.describe Msf::Post::Windows::Registry do
  subject do
    context_described_class = described_class

    klass = Class.new(Msf::Post) do
      include context_described_class
    end

    klass.new
  end

  describe '#split_key' do
    [
      { input: 'HKLM\\SOFTWARE\\Microsoft', expected: ['HKLM', 'SOFTWARE\\Microsoft'] },
      { input: 'HKLM\\SOFTWARE\\Microsoft\\', expected: ['HKLM', 'SOFTWARE\\Microsoft\\'] },
      { input: 'HKLM', expected: ['HKLM', nil] },
      { input: 'HKCU\\Environment', expected: ['HKCU', 'Environment'] },
      { input: 'HKU\\S-1-5-21-1234', expected: ['HKU', 'S-1-5-21-1234'] },
      { input: '', expected: ['', nil] },
    ].each do |test_case|
      it "splits #{test_case[:input].inspect} into #{test_case[:expected].inspect}" do
        expect(subject.send(:split_key, test_case[:input])).to eq(test_case[:expected])
      end
    end
  end

  describe '#normalize_key' do
    context 'with standard key paths' do
      [
        { input: 'HKLM\\SOFTWARE\\Microsoft', expected: 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft' },
        { input: 'HKCU\\Environment', expected: 'HKEY_CURRENT_USER\\Environment' },
        { input: 'HKU\\S-1-5-18', expected: 'HKEY_USERS\\S-1-5-18' },
        { input: 'HKCR\\.exe', expected: 'HKEY_CLASSES_ROOT\\.exe' },
        { input: 'HKCC\\System', expected: 'HKEY_CURRENT_CONFIG\\System' },
        { input: 'HKPD', expected: 'HKEY_PERFORMANCE_DATA' },
        { input: 'HKDD', expected: 'HKEY_DYN_DATA' },
      ].each do |test_case|
        it "normalizes #{test_case[:input].inspect} to #{test_case[:expected].inspect}" do
          expect(subject.send(:normalize_key, test_case[:input])).to eq(test_case[:expected])
        end
      end
    end

    context 'with trailing backslash' do
      it 'strips the trailing backslash from the normalized key' do
        result = subject.send(:normalize_key, 'HKLM\\SOFTWARE\\Microsoft\\')
        expect(result).to eq('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft')
        expect(result).not_to end_with('\\')
      end

      it 'produces the same result as a key without trailing backslash' do
        with_slash = subject.send(:normalize_key, 'HKLM\\SOFTWARE\\Microsoft\\')
        without_slash = subject.send(:normalize_key, 'HKLM\\SOFTWARE\\Microsoft')
        expect(with_slash).to eq(without_slash)
      end
    end

    context 'with root-only keys' do
      it 'returns the expanded root key without a trailing backslash' do
        result = subject.send(:normalize_key, 'HKLM')
        expect(result).to eq('HKEY_LOCAL_MACHINE')
        expect(result).not_to end_with('\\')
      end
    end

    context 'with already fully expanded root keys' do
      it 'returns the key unchanged' do
        expect(subject.send(:normalize_key, 'HKEY_LOCAL_MACHINE\\SOFTWARE')).to eq('HKEY_LOCAL_MACHINE\\SOFTWARE')
      end
    end

    context 'with an unknown root key' do
      it 'raises ArgumentError' do
        expect { subject.send(:normalize_key, 'BOGUS\\Key') }.to raise_error(ArgumentError)
      end
    end

    context 'idempotency' do
      it 'returns the same result when called twice' do
        key = 'HKLM\\SOFTWARE\\Microsoft\\'
        first = subject.send(:normalize_key, key)
        second = subject.send(:normalize_key, first)
        expect(first).to eq(second)
      end
    end
  end
end
