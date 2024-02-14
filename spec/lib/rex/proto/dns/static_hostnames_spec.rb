# -*- coding:binary -*-
require 'dnsruby'
require 'spec_helper'

RSpec.describe Rex::Proto::DNS::StaticHostnames do
  describe '#parse_hosts_file' do
    context 'when parsing a file' do
      let(:subject) { described_class.new }
      let(:hosts_file) {
        <<~CONTENT
          # this is a comment

          127.0.0.1 localhost localhost4
          ::1       localhost localhost6
          127.1.1.1 localhost
          thisIsInvalid
        CONTENT
      }

      before(:each) do
        expect(File).to receive(:file?).and_return(true)
        expect(File).to receive(:readable?).and_return(true)
        expect(::IO).to receive(:foreach) do |_, &block|
          hosts_file.split("\n").each do |line|
            block.call(line)
          end
        end
        subject.parse_hosts_file
      end

      it 'is not empty' do
        expect(subject.empty?).to be_falsey
      end

      context 'when no type is specified' do
        it 'returns an IPv4 address' do
          expect(subject.get('localhost')).to eq ['127.0.0.1', '127.1.1.1']
        end
      end

      it 'defines an IPv4 address for localhost' do
        expect(subject.get('localhost', Dnsruby::Types::A)).to eq ['127.0.0.1', '127.1.1.1']
      end

      it 'defines an IPv6 address for localhost' do
        expect(subject.get('localhost', Dnsruby::Types::AAAA)).to eq ['::1']
      end
    end
  end

  context 'when no hosts are defined' do
    let(:subject) { described_class.new }

    describe '#empty?' do
      it 'is true' do
        expect(subject.empty?).to be_truthy
      end
    end

    describe '#get' do
      it 'returns an empty array' do
        expect(subject.get('localhost')).to eq []
      end
    end

    describe '#get1' do
      it 'returns nil' do
        expect(subject.get1('localhost')).to be_nil
      end
    end

    describe '#length' do
      it 'is zero' do
        expect(subject.length).to eq 0
      end
    end
  end
end
