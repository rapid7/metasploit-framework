require 'rex/parser/winscp'

INI_SECURITY = "[Configuration\\Security]\nUseMasterPassword=1\nMasterPasswordVerifier=\n"

USERNAME = 'username'
HOST = 'server.feralhosting.com'
PASSWORD='A35C7659654B2AB83C292F392E323D31392F392E2A392E723A392E3D3034332F2835323B723F33312F383A2F383A3B2F3B3B3B'
SAMPLE_INI = <<-END
[Sessions\\username@server.feralhosting.com]
HostName=#{HOST}
Timeout=6000
SshProt=3
UserName=#{USERNAME}
UpdateDirectories=0
Utf=1
Password=#{PASSWORD}
Shell=/bin/bash}
END

RSpec.describe Rex::Parser::WinSCP do
  let(:target) do
    d = Class.new { include Rex::Parser::WinSCP }
    d.new
  end

  context "#parse_protocol" do
    it "returns 'Unknown' for unknown protocols" do
      expect(target.parse_protocol(nil)).to eq('Unknown')
      expect(target.parse_protocol(99)).to eq('Unknown')
      expect(target.parse_protocol('stuff')).to eq('Unknown')
    end

    it "returns 'SSH' for protocol 0" do
      expect(target.parse_protocol(0)).to eq('SSH')
    end

    it "returns 'FTP' for protocol 5" do
      expect(target.parse_protocol(5)).to eq('FTP')
    end
  end

  context "#decrypt_next_char" do
    it "returns 0 and the pwd if pwd length <= 0" do
      r, pwd = target.decrypt_next_char('')
      expect(r).to eq(0)
      expect(pwd).to eq('')
    end

    it "strips the first two characters from the return value" do
      _, pwd = target.decrypt_next_char('A3')
      expect(pwd).to eq('')
    end

    it "returns 255 for 'A3'" do
      r, _ = target.decrypt_next_char('A3')
      expect(r).to eq(Rex::Parser::WinSCP::PWDALG_SIMPLE_FLAG)
    end
  end

  context "#decrypt_password" do
    it "returns 'sdfsdfgsggg' for the example password" do
      expect(target.decrypt_password(PASSWORD, "#{USERNAME}#{HOST}")).to eq('sdfsdfgsggg')
    end
  end

  context "#parse_ini" do
    it "raises a RuntimeError if ini is nil or empty" do
      expect { target.parse_ini('') }.to raise_error(RuntimeError, /No data/i)
      expect { target.parse_ini(nil) }.to raise_error(RuntimeError, /No data/i)
    end

    it "raises a RuntimeError if UseMasterPassword is 1" do
      expect { target.parse_ini(INI_SECURITY) }.to raise_error(RuntimeError, /Master/i)
    end

    it "parses the example ini" do
      r = target.parse_ini(SAMPLE_INI).first
      expect(r[:hostname]).to eq(HOST)
      expect(r[:password]).to eq('sdfsdfgsggg')
      expect(r[:username]).to eq(USERNAME)
      expect(r[:protocol]).to eq('SSH')
      expect(r[:portnumber]).to eq(22)
    end
  end

  context "#read_and_parse_ini" do
    it "returns nil if file is empty or doesn't exist" do
      expect(File).to receive(:read).and_return(nil)
      expect(target.read_and_parse_ini('blah')).to be nil
    end

    it "parses the example ini and return a single result" do
      expect(File).to receive(:read).and_return(SAMPLE_INI)
      expect(target.read_and_parse_ini(SAMPLE_INI).count).to eq 1
    end
  end
end

