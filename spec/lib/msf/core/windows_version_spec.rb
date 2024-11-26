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
    subject = described_class.new(10,0,18362,0, 0,Msf::WindowsVersion::VER_NT_WORKSTATION)
    expect(subject.to_s).to eq('Windows 10+ Build 18362')
  end

  it 'Adds service pack suffix' do
    subject = described_class.new(5,1,2600,2, 0,Msf::WindowsVersion::VER_NT_WORKSTATION)
    expect(subject.to_s).to eq('Windows XP Service Pack 2')
  end

  it 'Outputs unknown version' do
    subject = described_class.new(1,2,3000,0, 0,Msf::WindowsVersion::VER_NT_WORKSTATION)
    expect(subject.to_s).to eq('Unknown Windows version: 1.2.3000')
  end
end
