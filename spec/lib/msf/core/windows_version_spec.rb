require 'spec_helper'

RSpec.describe Msf::WindowsVersion do

  it 'Recognisises a major version' do
    subject = described_class.new(6, 0, 6000, 0, 0, Msf::WindowsVersion::VER_NT_WORKSTATION)
    expect(subject.to_s).to eq('Windows Vista')
  end

  it 'Recognisises Windows Server' do
    subject = described_class.new(6, 0, 6000, 0, 0, Msf::WindowsVersion::VER_NT_SERVER)
    expect(subject.to_s).to eq('Windows Server 2008')
  end

  it 'Adds build suffix to Windows 10' do
    subject = described_class.new(10,0,18360,0, 0,Msf::WindowsVersion::VER_NT_WORKSTATION)
    expect(subject.to_s).to eq('Windows 10+ Build 18360')
  end

  it 'Uses known Windows 10 version' do
    subject = described_class.new(10,0,18362,0, 0,Msf::WindowsVersion::VER_NT_WORKSTATION)
    expect(subject.to_s).to eq('Windows 10 version 1903')
  end

  it 'Adds service pack suffix' do
    subject = described_class.new(5,1,2602,2, 0,Msf::WindowsVersion::VER_NT_WORKSTATION)
    expect(subject.to_s).to eq('Windows XP Service Pack 2')
  end

  it 'Outputs unknown version' do
    subject = described_class.new(1,2,3000,0, 0,Msf::WindowsVersion::VER_NT_WORKSTATION)
    expect(subject.to_s).to eq('Unknown Windows version: 1.2.3000')
  end

  it 'Has string name for each named version' do
    described_class::ServerSpecificVersions.constants.each do |version_sym|
      expect(described_class::ServerNameMapping).to include(version_sym)
    end
    described_class::WorkstationSpecificVersions.constants.each do |version_sym|
      expect(described_class::WorkstationNameMapping).to include(version_sym)
    end
  end

  it 'Reports correct SMB version for single match' do
    major = 5
    minor = 1
    build = 2600
    version_string = described_class.from_ntlm_os_version(major, minor, build)
    expect(version_string).to eq('Windows XP')
  end

  it 'Reports correct SMB version for multiple matches' do
    major = 6
    minor = 1
    build = 7601
    version_string = described_class.from_ntlm_os_version(major, minor, build)
    expect(version_string).to eq('Windows 7 Service Pack 1/Windows Server 2008 R2 Service Pack 1')
  end

  it 'Reports unknown SMB version for no identical old OS' do
    major = 6
    minor = 1
    build = 7604
    version_string = described_class.from_ntlm_os_version(major, minor, build)
    expect(version_string).to eq(nil)
  end

  it 'Reports unknown SMB version for no identical Win10+' do
    major = 10
    minor = 0
    build = 15064
    version_string = described_class.from_ntlm_os_version(major, minor, build)
    expect(version_string).to eq(nil)
  end
end
