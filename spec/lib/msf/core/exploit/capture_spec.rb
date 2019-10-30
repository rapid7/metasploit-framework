# -*- coding:binary -*-
require 'spec_helper'

require 'msf/core'
require 'msf/core/module'
require 'msf/core/exploit/capture'

RSpec.describe Msf::Exploit::Capture do

  subject do
    mod = Msf::Module.new
    mod.extend described_class
    mod
  end

  it 'should be a kind of Msf::Exploit::Capture' do
    expect(subject).to be_a_kind_of Msf::Exploit::Capture
  end

  context '#capture_sendto' do
    let(:payload) { Rex::Text::rand_text_alphanumeric(100 + rand(1024)) }

    before(:example) do
      allow(subject).to receive(:capture).and_return(true)
    end

    it 'should return the correct number of bytes if the destination MAC can be determined, regardless of broadcast' do
      allow(subject).to receive(:lookup_eth).and_return(%w(de:ad:be:ef:ca:fe 01:02:03:04:05:06))
      allow(subject).to receive(:inject_eth).and_return(payload.size)
      expect(subject.capture_sendto(payload, '127.0.0.1', false)).to eq payload.size
      expect(subject.capture_sendto(payload, '127.0.0.1', true)).to eq payload.size
    end

    it 'should return false if the destination MAC cannot be determined and broadcast is not desired' do
      allow(subject).to receive(:lookup_eth).and_return(nil)
      expect(subject.capture_sendto(payload, '127.0.0.1')).to be_falsey
      expect(subject.capture_sendto(payload, '127.0.0.1', false)).to be_falsey
    end

    it 'should return the correct number of bytes if the destination MAC cannot be determined and broadcast is desired' do
      allow(subject).to receive(:lookup_eth).and_return(nil)
      allow(subject).to receive(:inject_eth).and_return(payload.size)
      expect(subject.capture_sendto(payload, '127.0.0.1', true)).to eq payload.size
    end

  end

  context '#stats_*' do

    it 'should show received packets' do
      expect(subject.stats_recv).to eq 0
    end

    it 'should show dropped packets' do
      expect(subject.stats_drop).to eq 0
    end

    it 'should show interface-dropped packets' do
      expect(subject.stats_ifdrop).to eq 0
    end

  end

  it 'should respond to open_pcap' do
    expect(subject).to respond_to :open_pcap
  end

  it 'should confirm that pcaprub is available', :skip => "Need to test this without stubbing check_pcaprub_loaded" do
  end

  it 'should open a pcap file', :skip => "Provde a sample pcap file to read" do
  end

  it 'should capture from an iface', :skip => "Mock this? Tends to need root" do
  end

  it 'should inject packets to an ifrace', :skip => "Mock this? Tends to need root" do
  end

end

