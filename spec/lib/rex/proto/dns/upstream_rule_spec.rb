# -*- coding:binary -*-
require 'spec_helper'
require 'rex/text'

RSpec.describe Rex::Proto::DNS::UpstreamRule do
  describe '.spell_check_resolver' do
    it 'returns nil for IPv4 addresses' do
      address = Rex::Socket.addr_ntoa(Random.new.bytes(4))
      expect(described_class.spell_check_resolver(address)).to be_nil
    end

    it 'returns nil for IPv6 addresses' do
      address = Rex::Socket.addr_ntoa(Random.new.bytes(16))
      expect(described_class.spell_check_resolver(address)).to be_nil
    end

    it 'returns nil for "black-hole"' do
      expect(described_class.spell_check_resolver('black-hole')).to be_nil
    end

    it 'returns a populated array for "blackhole"' do
      suggestions = described_class.spell_check_resolver('blackhole')
      expect(suggestions).to be_a Array
      expect(suggestions.first).to eq 'black-hole'
    end
  end

  describe '.valid_resolver?' do
    it 'returns true for "black-hole"' do
      expect(described_class.valid_resolver?('black-hole')).to be_truthy
      expect(described_class.valid_resolver?('Black-Hole')).to be_truthy
      expect(described_class.valid_resolver?(%s[black-hole])).to be_truthy
    end

    it 'returns true for IPv4 addresses' do
      address = Rex::Socket.addr_ntoa(Random.new.bytes(4))
      expect(described_class.valid_resolver?(address)).to be_truthy
    end

    it 'returns true for IPv6 addresses' do
      address = Rex::Socket.addr_ntoa(Random.new.bytes(16))
      expect(described_class.valid_resolver?(address)).to be_truthy
    end

    it 'returns true for "static"' do
      expect(described_class.valid_resolver?('static')).to be_truthy
      expect(described_class.valid_resolver?('Static')).to be_truthy
      expect(described_class.valid_resolver?(:static)).to be_truthy
    end

    it 'returns true for "system"' do
      expect(described_class.valid_resolver?('system')).to be_truthy
      expect(described_class.valid_resolver?('System')).to be_truthy
      expect(described_class.valid_resolver?(:system)).to be_truthy
    end

    it 'raises returns false for invalid resolvers' do
      expect(described_class.valid_resolver?('fake')).to be_falsey
    end
  end

  context 'when using a wildcard condition' do
    let(:subject) { described_class.new(wildcard: '*.metasploit.com') }

    describe '#matches_all?' do
      it 'does not return true for everything' do
        expect(subject.matches_all?).to be_falsey
      end
    end

    describe '#matches_name?' do
      it 'returns true for subdomains' do
        expect(subject.matches_name?('www.metasploit.com')).to be_truthy
      end

      it 'returns true for subsubdomains' do
        expect(subject.matches_name?('one.two.metasploit.com')).to be_truthy
      end

      it 'returns false for the domain' do
        expect(subject.matches_name?('metasploit.com')).to be_falsey
      end


      it 'returns false for other domains' do
        expect(subject.matches_name?('notmetasploit.com')).to be_falsey
      end
    end
  end

  context 'when not using a wildcard condition' do
    let(:subject) { described_class.new }

    describe '#wildcard' do
      it 'defaults to *' do
        expect(subject.wildcard).to eq '*'
      end
    end

    describe '#matches_all?' do
      it 'returns true for everything' do
        expect(subject.matches_all?).to be_truthy
      end
    end

    describe '#matches_name?' do
      it 'returns true for everything' do
        expect(subject.matches_name?("#{Rex::Text.rand_text_alphanumeric(10)}.#{Rex::Text.rand_text_alphanumeric(3)}")).to be_truthy
      end
    end
  end
end
