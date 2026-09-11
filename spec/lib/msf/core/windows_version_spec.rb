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

  describe '.from_target_name' do
    context 'with a single, specific workstation version' do
      {
        'Windows 7' => described_class::Win7_SP0,
        'Windows 7 SP1' => described_class::Win7_SP1,
        'Windows 7 SP1 x64' => described_class::Win7_SP1,
        'CyberLink LabelPrint <= 2.5 on Windows 7 (64 bit)' => described_class::Win7_SP0,
        'Windows XP SP3' => described_class::XP_SP3,
        'on Windows XP SP3 English (w/DEP bypass)' => described_class::XP_SP3,
        'Windows Vista' => described_class::Vista_SP0,
        'Windows 8' => described_class::Win8,
        'Windows 8.1 x64' => described_class::Win81,
        'Windows 11' => described_class::Win11_21H2
      }.each do |name, expected|
        it "resolves #{name.inspect} to #{expected}" do
          expect(described_class.from_target_name(name)).to eq(expected)
        end
      end
    end

    context 'with a single, specific server version' do
      {
        'Server 2003 Sp2' => described_class::Server2003_SP2,
        'Windows Server 2003 English SP0/SP1' => described_class::Server2003_SP0,
        'Windows Server 2008 R2' => described_class::Server2008_R2_SP0,
        'Windows Server 2008 R2 SP1' => described_class::Server2008_R2_SP1,
        'Windows Server 2012 R2' => described_class::Server2012_R2,
        'Windows Server 2016' => described_class::Server2016
      }.each do |name, expected|
        it "resolves #{name.inspect} to #{expected}" do
          expect(described_class.from_target_name(name)).to eq(expected)
        end
      end
    end

    context 'when multiple service packs are referenced for one family' do
      it 'returns the oldest as the minimum version' do
        expect(described_class.from_target_name('Windows XP SP2/SP3')).to eq(described_class::XP_SP2)
        expect(described_class.from_target_name('Windows XP SP0/SP1')).to eq(described_class::XP_SP0)
      end
    end

    context 'with Windows 2000 service packs' do
      it 'maps SP0-SP3 to the base build and SP4 to its specific build' do
        expect(described_class.from_target_name('Windows 2000 SP0-SP4 English')).to eq(described_class::Win2000)
        expect(described_class.from_target_name('Windows 2000 SP4 English')).to eq(described_class::Win2000_SP4)
      end
    end

    context 'with a generic name that does not specify a version' do
      ['Windows', 'Windows x64', 'Windows Universal', 'Windows (All)', 'Automatic'].each do |name|
        it "returns nil for #{name.inspect}" do
          expect(described_class.from_target_name(name)).to be_nil
        end
      end
    end

    context 'with a name that references several different versions' do
      [
        'Chasys Draw IES 4.10.01 / Windows XP SP3 / Windows 7 SP1',
        'Adobe Reader v8.x / Windows XP SP3 / Windows Vista/7/10',
        '<Win Xp, Win 7, Win 8, Win 10>'
      ].each do |name|
        it "returns nil for the ambiguous name #{name.inspect}" do
          expect(described_class.from_target_name(name)).to be_nil
        end
      end
    end

    context 'with a non-Windows name' do
      ['Linux x86', 'PHP', 'Java Universal', 'Apple macOS'].each do |name|
        it "returns nil for #{name.inspect}" do
          expect(described_class.from_target_name(name)).to be_nil
        end
      end
    end

    it 'does not treat unrelated software release years as an OS version' do
      # The year is not preceded by "Windows"/"Server", so it must not be read
      # as a Server SKU.
      expect(described_class.from_target_name('SomeApp 2016 on Linux')).to be_nil
    end

    it 'does not treat a CVE year as an OS version' do
      # "2019" here is part of a CVE id, so the name resolves to Windows 7 only
      # rather than being treated as ambiguous (Windows 7 + Server 2019).
      name = 'Windows 7 (x64) sandbox escape via CVE-2019-1458'
      expect(described_class.from_target_name(name)).to eq(described_class::Win7_SP0)
    end

    it 'does not match a bare version number without a Windows prefix' do
      # "8.1" here is a product version, not Windows 8.1.
      expect(described_class.from_target_name('BEA WebLogic 8.1 SP4')).to be_nil
    end

    it 'returns nil for non-string input' do
      expect(described_class.from_target_name(nil)).to be_nil
      expect(described_class.from_target_name('')).to be_nil
    end
  end
end
