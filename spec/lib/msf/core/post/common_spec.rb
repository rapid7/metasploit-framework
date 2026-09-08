# -*- coding: binary -*-
# frozen_string_literal: true

require 'spec_helper'
require 'msf/core/post/common'

RSpec.describe Msf::Post::Common do
  subject(:post_module) do
    described_mixin = described_class
    klass = Class.new do
      include described_mixin

      attr_accessor :session
    end

    obj = klass.allocate
    obj.session = session
    obj
  end

  let(:process_manager) { double('process_manager') }
  let(:sys) { double('sys', process: process_manager) }
  let(:session) do
    Struct.new(:type, :response_timeout, :platform, :arch, :sys).new(
      'meterpreter',
      300,
      'linux',
      ARCH_X64,
      sys
    )
  end

  describe '#create_process' do
    it 'restores the meterpreter response timeout after process output capture' do
      allow(process_manager).to receive(:capture_output).and_return("uid=0\n")

      expect(post_module.create_process('/usr/bin/id', time_out: 15)).to eq("uid=0\n")
      expect(session.response_timeout).to eq(300)
    end

    it 'restores the meterpreter response timeout when process output capture raises an exception' do
      allow(process_manager).to receive(:capture_output).and_raise(Rex::TimeoutError)

      expect { post_module.create_process('/usr/bin/id', time_out: 15) }.to raise_error(Rex::TimeoutError)
      expect(session.response_timeout).to eq(300)
    end

    it 'preserves the non-channelized return value while restoring the meterpreter response timeout' do
      allow(process_manager).to receive(:execute).and_return(double('process'))

      expect(post_module.create_process('/usr/bin/id', time_out: 15, opts: { 'Channelized' => false })).to eq('')
      expect(session.response_timeout).to eq(300)
    end
  end

  describe '#cmd_exec' do
    it 'restores the meterpreter response timeout after command output capture' do
      allow(process_manager).to receive(:capture_output).and_return("uid=0\n")

      expect(post_module.cmd_exec('/usr/bin/id', nil, 15)).to eq("uid=0\n")
      expect(session.response_timeout).to eq(300)
    end

    it 'restores the meterpreter response timeout when command output capture raises an exception' do
      allow(process_manager).to receive(:capture_output).and_raise(Rex::TimeoutError)

      expect { post_module.cmd_exec('/usr/bin/id', nil, 15) }.to raise_error(Rex::TimeoutError)
      expect(session.response_timeout).to eq(300)
    end

    it 'preserves the non-channelized return value while restoring the meterpreter response timeout' do
      allow(process_manager).to receive(:execute).and_return(double('process'))

      expect(post_module.cmd_exec('/usr/bin/id', nil, 15, 'Channelized' => false)).to eq('')
      expect(session.response_timeout).to eq(300)
    end
  end

  describe '#cmd_exec_get_pid' do
    let(:channel) { double('channel', close: nil) }
    let(:process) { double('process', channel: channel, close: nil, pid: 1234) }

    it 'restores the meterpreter response timeout after process execution' do
      allow(process_manager).to receive(:execute).and_return(process)

      expect(post_module.cmd_exec_get_pid('/bin/sleep', '10', 15)).to eq(1234)
      expect(session.response_timeout).to eq(300)
    end

    it 'restores the meterpreter response timeout when process execution raises an exception' do
      allow(process_manager).to receive(:execute).and_raise(Rex::TimeoutError)

      expect { post_module.cmd_exec_get_pid('/bin/sleep', '10', 15) }.to raise_error(Rex::TimeoutError)
      expect(session.response_timeout).to eq(300)
    end
  end
end
