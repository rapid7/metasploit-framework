# -*- coding: binary -*-
require 'spec_helper'

require 'msf/core/auxiliary/recog'

describe Msf::Auxiliary::Recog do
  subject do
    mod = Msf::Module.new
    mod.extend described_class
    mod.extend Msf::Auxiliary::Report
    mod.send(:initialize, {})
    mod
  end

  let(:banner) { 'xx Microsoft FTP Service (Version 3.0).' }

  describe '#report_recog_info' do
    context 'should use recog only when told to' do
      before(:each) do
        allow(subject).to receive(:rhost).and_return('192.168.255.255')
      end
      it 'should when told to' do
        subject.datastore['UseRecog'] = true
        match = subject.report_recog_info('blah', 'ftp.banner', banner)
        match.should == {
          "matched"=>"Microsoft FTP Server on Windows NT",
          "service.vendor"=>"Microsoft",
          "service.product"=>"IIS",
          "service.family"=>"IIS",
          "service.version"=>"3.0",
          "os.vendor"=>"Microsoft",
          "os.device"=>"General",
          "os.family"=>"Windows",
          "os.product"=>"Windows NT",
          "host.name"=>"xx"
        }
      end

      it 'should not when told not to' do
        subject.datastore['UseRecog'] = false
        match = subject.report_recog_info('blah', 'ftp.banner', banner)
        match.should be nil
      end
    end
  end
end
