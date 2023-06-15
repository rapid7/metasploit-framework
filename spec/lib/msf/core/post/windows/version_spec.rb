# -*- coding: binary -*-
require 'spec_helper'

RSpec.describe Msf::Post::Windows::Version do

  subject do
    context_described_class = described_class

    klass = Class.new(Msf::Post) do
      include context_described_class
    end

    klass.new
  end

  def respond_to_reg_query(subject, key, value, result, type)
    command = "cmd.exe /c reg query \"#{key}\" /v \"#{value}\""
    output = "\r\n#{key}\r\n    #{value}    #{type}    #{result}\r\n"
    allow(subject).to receive(:cmd_exec).with(command) { output }
  end

  let(:current_version_key) do
    'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
  end

  let(:current_build_number) do
    'CurrentBuildNumber'
  end

  let(:current_version) do
    'CurrentVersion'
  end

  let(:service_pack) do
    'CSDVersion'
  end

  let(:minor_version) do
    'CurrentMinorVersionNumber'
  end

  let(:major_version) do
    'CurrentMajorVersionNumber'
  end

  let(:ubr) do
    'UBR'
  end

  let(:product_type_key) do
    'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\ProductOptions'
  end

  let(:product_type) do
    'ProductType'
  end

  context "#calculates_version_num" do
    it "XP SP2" do
      respond_to_reg_query(subject, current_version_key, current_build_number, '2600', 'REG_SZ')
      respond_to_reg_query(subject, current_version_key, current_version, '5.1', 'REG_SZ')
      respond_to_reg_query(subject, current_version_key, service_pack, 'Service Pack 2', 'REG_SZ')
      respond_to_reg_query(subject, product_type_key, product_type, 'WinNT', 'REG_SZ')
      allow(subject).to receive_message_chain('session.type').and_return('shell')
      version = subject.get_version_info
      expect(version.build_number).to eq(Msf::WindowsVersion::XP_SP2)
      expect(version.windows_server?).to eq(false)
      expect(version.domain_controller?).to eq(false)
    end

    it "2003 SP1" do
      respond_to_reg_query(subject, current_version_key, current_build_number, '3790', 'REG_SZ')
      respond_to_reg_query(subject, current_version_key, current_version, '5.2', 'REG_SZ')
      respond_to_reg_query(subject, current_version_key, service_pack, 'Service Pack 1', 'REG_SZ')
      respond_to_reg_query(subject, product_type_key, product_type, 'ServerNT', 'REG_SZ')
      allow(subject).to receive_message_chain('session.type').and_return('shell')
      version = subject.get_version_info
      expect(version.build_number).to eq(Msf::WindowsVersion::Server2003_SP1)
      expect(version.windows_server?).to eq(true)
      expect(version.domain_controller?).to eq(false)
    end

    it "Win10" do
      respond_to_reg_query(subject, current_version_key, current_build_number, '19045', 'REG_SZ')
      respond_to_reg_query(subject, current_version_key, current_version, '6.3', 'REG_SZ')
      respond_to_reg_query(subject, current_version_key, major_version, '0xa', 'REG_DWORD')
      respond_to_reg_query(subject, current_version_key, minor_version, '0x0', 'REG_DWORD')
      respond_to_reg_query(subject, current_version_key, ubr, '0x100', 'REG_DWORD')
      respond_to_reg_query(subject, product_type_key, product_type, 'WinNT', 'REG_SZ')
      allow(subject).to receive_message_chain('session.type').and_return('shell')
      version = subject.get_version_info
      expect(version.build_number).to eq(Msf::WindowsVersion::Win10_22H2)
      expect(version.revision_number).to eq(256)
      expect(version.windows_server?).to eq(false)
      expect(version.domain_controller?).to eq(false)
    end

    it "Server 2022" do
      respond_to_reg_query(subject, current_version_key, current_build_number, '20348', 'REG_SZ')
      respond_to_reg_query(subject, current_version_key, current_version, '6.3', 'REG_SZ')
      respond_to_reg_query(subject, current_version_key, major_version, '0xa', 'REG_DWORD')
      respond_to_reg_query(subject, current_version_key, minor_version, '0x0', 'REG_DWORD')
      respond_to_reg_query(subject, current_version_key, ubr, '0x100', 'REG_DWORD')
      respond_to_reg_query(subject, product_type_key, product_type, 'LanmanNT', 'REG_SZ')
      allow(subject).to receive_message_chain('session.type').and_return('shell')
      version = subject.get_version_info
      expect(version.build_number).to eq(Msf::WindowsVersion::Server2022)
      expect(version.revision_number).to eq(256)
      expect(version.windows_server?).to eq(true)
      expect(version.domain_controller?).to eq(true)
    end

    it "Windows 2000 German" do
      allow(subject).to receive(:cmd_exec).with("cmd.exe /c reg query \"#{current_version_key}\" /v \"#{current_build_number}\"") { "Der Befehl \"reg\" ist entweder falsch geschrieben oder\r\nkonnte nicht gefunden werden." }
      allow(subject).to receive(:cmd_exec).with("cmd.exe /c ver") { "Microsoft Windows 2000 [Version 5.00.2195]" }
      allow(subject).to receive_message_chain('session.type').and_return('shell')
      version = subject.get_version_info
      expect(version.build_number).to eq(Msf::WindowsVersion::Win2000)
      expect(version.windows_server?).to eq(false)
      expect(version.domain_controller?).to eq(false)
    end

  end
end
