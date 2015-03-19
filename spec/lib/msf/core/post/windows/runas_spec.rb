# -*- coding: binary -*-
require 'spec_helper'

require 'msf/core/post/windows/runas'

describe Msf::Post::Windows::Runas do
  let(:process_info) do
    "\x01\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00\x00\x04\x00\x00\x00"
  end

  let(:phToken) do
    "testPhToken"
  end

  let(:advapi32) do
    advapi32 = double('advapi32')
    advapi32.stub(:CreateProcessWithLogonW).and_return({
                        'return' => true,
                        'lpProcessInformation' => process_info
    })
    advapi32.stub(:CreateProcessAsUserA).and_return ({
      'return' => true,
      'lpProcessInformation' => process_info
    })
    advapi32.stub(:LogonUserA).and_return ({
      'return' => true,
      'phToken' => phToken
    })
    advapi32
  end

  let(:kernel32) do
    double('kernel32', CloseHandle: nil)
  end

  let(:subject) do
    mod = Module.new
    mod.extend described_class
    stubs = [ :vprint_status, :print_status, :vprint_good, :print_good, :print_error ]
    stubs.each { |meth| mod.stub(meth) }
    mod.stub_chain("session.railgun.kernel32").and_return(kernel32)
    mod.stub_chain("session.railgun.advapi32").and_return(advapi32)
    mod
  end

  context "#create_process_with_logon" do
    it "should return a process_info hash" do
      expect(advapi32).to receive(:CreateProcessWithLogonW)
      expect(kernel32).not_to receive(:CloseHandle)
      pi = subject.create_process_with_logon(nil, 'bob', 'pass', nil, 'cmd.exe')
      pi.should be_kind_of(Hash)
      pi.should eq(process_handle: 1, thread_handle: 2, process_id: 3, thread_id: 4)
    end

    it "should return a nil on failure" do
      expect(advapi32).to receive(:CreateProcessWithLogonW)
      expect(kernel32).not_to receive(:CloseHandle)
      advapi32.stub(:CreateProcessWithLogonW).and_return('return' => false, 'GetLastError' => 1783, 'ErrorMessage' => 'parp')
      subject.create_process_with_logon(nil, 'bob', 'pass', nil, 'cmd.exe').should be nil
    end
  end

  context "#create_process_as_user" do
    it "should return a process_info hash" do
      expect(advapi32).to receive(:LogonUserA)
      expect(advapi32).to receive(:CreateProcessAsUserA)
      expect(kernel32).to receive(:CloseHandle).with(phToken)
      expect(kernel32).to receive(:CloseHandle).with(1)
      expect(kernel32).to receive(:CloseHandle).with(2)
      pi = subject.create_process_as_user(nil, 'bob', 'pass', nil, 'cmd.exe')
      pi.should be_kind_of(Hash)
      pi.should eq(process_handle: 1, thread_handle: 2, process_id: 3, thread_id: 4)
    end

    it "should return a nil on failure of create process" do
      expect(advapi32).to receive(:LogonUserA)
      expect(advapi32).to receive(:CreateProcessAsUserA)
      expect(kernel32).to receive(:CloseHandle).with(phToken)
      expect(kernel32).not_to receive(:CloseHandle).with(1)
      expect(kernel32).not_to receive(:CloseHandle).with(2)
      advapi32.stub(:CreateProcessAsUserA).and_return('return' => false, 'GetLastError' => 1783, 'ErrorMessage' => 'parp')
      subject.create_process_as_user(nil, 'bob', 'pass', nil, 'cmd.exe').should be nil
    end

    it "should return a nil on failure of logon user" do
      expect(advapi32).to receive(:LogonUserA)
      expect(advapi32).not_to receive(:CreateProcessAsUserA)
      expect(kernel32).not_to receive(:CloseHandle).with(phToken)
      expect(kernel32).not_to receive(:CloseHandle).with(1)
      expect(kernel32).not_to receive(:CloseHandle).with(2)
      advapi32.stub(:LogonUserA).and_return('return' => false, 'GetLastError' => 1783, 'ErrorMessage' => 'parp')
      subject.create_process_as_user(nil, 'bob', 'pass', nil, 'cmd.exe').should be nil
    end
  end

  context "#startup_info" do
    it "should be 68 bytes" do
      subject.startup_info.size.should eq(68)
    end

    it "should return SW_HIDE=0 and STARTF_USESHOWWINDOW=1" do
      si = subject.startup_info.unpack('VVVVVVVVVVVVvvVVVV')
      si[11].should eq(1)
      si[12].should eq(0)
    end
  end

  context "#parse_process_information" do
    it "should return a hash when given valid data" do
      pi = subject.parse_process_information(process_info)
      pi.should be_kind_of(Hash)
      pi.should eq(process_handle: 1, thread_handle: 2, process_id: 3, thread_id: 4)
    end

    it "should return an exception when given an empty string" do
      expect { subject.parse_process_information("") }.to raise_error
    end

    it "should return an exception when given an nil value" do
      expect { subject.parse_process_information(nil) }.to raise_error
    end
  end

  context "#check_user_format" do
    let(:upn_username) do
      "bob@flob.com"
    end
    let(:domain_username) do
      "flob\\bob"
    end
    let(:domain) do
      "flob"
    end

    it "should return an exception when username is nil" do
      expect { subject.check_user_format(nil, domain) }.to raise_error
    end

    it "should return an exception when UPN format and domain supplied" do
      expect { subject.check_user_format(upn_username, domain) }.to raise_error
    end

    it "should return true when UPN format and domain is nil" do
      subject.check_user_format(upn_username, nil).should be true
    end

    it "should return true when domain format and domain is nil" do
      subject.check_user_format(domain_username, nil).should be true
    end

    it "should return true when domain format and domain supplied" do
      subject.check_user_format(domain_username, domain).should be true
    end
  end

  context "#check_command_length" do
    let(:max_length) do
      1024
    end
    let(:max_path) do
      256
    end
    let(:large_command_module) do
      ("A" * max_path + 1) + " arg1 arg2"
    end
    let(:normal_command_module) do
      ("A" * max_path) + " arg1 arg2"
    end
    let(:large_command_line) do
      "A" * max_length + 1
    end
    let(:normal_command_line) do
      "A" * max_length
    end
    let(:application_name) do
      "c:\\windows\\system32\\calc.exe"
    end

    it "should raise an exception when max_length is nil" do
      expect { subject.check_command_length(nil, nil, nil) }.to raise_error
    end

    it "should raise an exception when application_name and command_line are nil" do
      expect { subject.check_command_length(nil, nil, max_length) }.to raise_error
    end

    it "should return true when application_name is set and command_line is nil" do
      subject.check_command_length(application_name, nil, max_length).should be true
    end

    it "should return true when application_name is set and command_line is max_length" do
      subject.check_command_length(application_name, normal_command_line, max_length).should be true
    end

    it "should raise an exception when command_line is larger than max_length" do
      expect { subject.check_command_length(nil, large_command_line, max_length) }.to raise_error
    end

    it "should raise an exception when application_name is nil command_line module is larger than MAX_PATH" do
      expect { subject.check_command_length(nil, large_command_module, max_length) }.to raise_error
    end

    it "should return true when application_name is nil and command_module is less than MAX_PATH" do
      subject.check_command_length(nil, normal_command_module, max_length).should be true
    end
  end
end
