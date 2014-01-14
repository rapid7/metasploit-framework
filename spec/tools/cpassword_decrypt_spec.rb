require 'spec_helper'

load Metasploit::Framework.root.join('tools/cpassword_decrypt.rb').to_path

require 'fastlib'
require 'msfenv'
require 'msf/base'

describe CPassword do
  context "Class methods" do
    let(:cpasswd) do
      CPassword.new
    end

    context ".decrypt" do
      it "should return the decrypted password as 'testpassword'" do
        # Encrypted password for "testpassword"
        cpass = "AzVJmXh/J9KrU5n0czX1uBPLSUjzFE8j7dOltPD8tLk"
        pass = cpasswd.decrypt(cpass)
        pass.should eq('testpassword')
      end

      it "should return an empty string due to a bad password" do
        # Invalid password format
        cpass = "BadPassword"
        pass = cpasswd.decrypt(cpass)
        pass.should eq('')
      end
    end
  end
end