# -*- coding: binary -*-
require 'spec_helper'
require 'rex/proto/quake/message'

RSpec.describe Rex::Proto::Quake do
  subject do
    mod = Module.new
    mod.extend described_class
    mod
  end

  describe '#encode_message' do
    it 'should properly encode messages' do
      message = subject.encode_message('getinfo')
      expect(message).to eq("\xFF\xFF\xFF\xFFgetinfo")
    end
  end

  describe '#decode_message' do
    it 'should not decode overly short messages' do
      expect(subject.decode_message('foo')).to eq(nil)
    end

    it 'should not decode unknown messages' do
      expect(subject.decode_message("\xFF\xFF\xFF\x01blahblahblah")).to eq(nil)
    end

    it 'should properly decode valid messages' do
      expect(subject.decode_message(subject.getstatus)).to eq('getstatus')
    end
  end

  describe '#decode_infostring' do
    it 'should not decode things that are not infostrings' do
      expect(subject.decode_infostring('this is not an infostring')).to eq(nil)
    end

    it 'should properly decode infostrings' do
      expect(subject.decode_infostring('a\1\b\2\c\blah')).to eq(
        'a' => '1', 'b' => '2', 'c' => 'blah'
      )
    end
  end

  describe '#decode_response' do
    it 'should raise when server-side errors are encountered' do
      expect do
        subject.decode_response(subject.encode_message("print\nsomeerror\n"))
      end.to raise_error(::ArgumentError)
    end
  end

  describe '#decode_info' do
    it 'should decode info responses properly' do
      expected_info = {
        "clients" => "0",
        "g_humanplayers" => "0",
        "g_needpass" => "0",
        "gamename" => "Quake3Arena",
        "gametype" => "0",
        "hostname" => "noname",
        "mapname" => "q3dm2",
        "protocol" => "68",
        "pure" => "1",
        "sv_maxclients" => "8",
        "voip" => "1"
      }
      actual_info = subject.decode_info(IO.read(File.join(File.dirname(__FILE__), 'info_response.bin')))
      expect(actual_info).to eq(expected_info)
    end
  end

  describe '#decode_status' do
    it 'should decode status responses properly' do
      expected_status = {
        "bot_minplayers" => "0",
        "capturelimit" => "8",
        "com_gamename" => "Quake3Arena",
        "com_protocol" => "71",
        "dmflags" => "0",
        "fraglimit" => "30",
        "g_gametype" => "0",
        "g_maxGameClients" => "0",
        "g_needpass" => "0",
        "gamename" => "baseq3",
        "mapname" => "q3dm2",
        "sv_allowDownload" => "0",
        "sv_dlRate" => "100",
        "sv_floodProtect" => "1",
        "sv_hostname" => "noname",
        "sv_maxPing" => "0",
        "sv_maxRate" => "10000",
        "sv_maxclients" => "8",
        "sv_minPing" => "0",
        "sv_minRate" => "0",
        "sv_privateClients" => "0",
        "timelimit" => "25",
        "version" => "ioq3 1.36+svn2202-1/Ubuntu linux-x86_64 Dec 12 2011"
      }
      actual_status = subject.decode_status(IO.read(File.join(File.dirname(__FILE__), 'status_response.bin')))
      expect(actual_status).to eq(expected_status)
    end
  end
end
