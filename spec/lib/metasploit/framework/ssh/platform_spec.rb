require 'spec_helper'
require 'metasploit/framework/ssh/platform'

RSpec.describe Metasploit::Framework::Ssh::Platform do
  describe '.get_platform_from_info' do
    [
      {
        info: 'uid=197616(vagrant) gid=197121(None) groups=197121(None),11(Authenticated Users),66048(LOCAL),66049(CONSOLE LOGON),4(INTERACTIVE),15(This Organization),545(Users),4095(CurrentSession),544(Administrators),559(Performance Log Users),405504(High Mandatory Level) MSYS_NT-10.0-17763 EC2AMAZ-PDSMQ8L 3.4.9.x86_64 2023-09-15 12:15 UTC x86_64 Msys ',
        expected: 'windows'
      }
    ].each do |test|
      it "correctly identifies #{test[:info]} as #{test[:expected]}" do
        expect(described_class.get_platform_from_info(test[:info])).to eq(test[:expected])
      end
    end
  end
end
