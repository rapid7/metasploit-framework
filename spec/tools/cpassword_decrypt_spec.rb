require 'spec_helper'

load Metasploit::Framework.root.join('tools/password/cpassword_decrypt.rb').to_path

require 'msfenv'
require 'msf/base'

RSpec.describe CPassword do
  context "Class methods" do
    let(:cpasswd) do
      CPassword.new
    end

    context ".decrypt" do
      it "should return the decrypted password as 'testpassword'" do
        # Encrypted password for "testpassword"
        cpass = "AzVJmXh/J9KrU5n0czX1uBPLSUjzFE8j7dOltPD8tLk"
        pass = cpasswd.decrypt(cpass)
        expect(pass).to eq('testpassword')
      end

      it "should return an empty string due to a bad password" do
        # Invalid password format
        cpass = "BadPassword"
        pass = cpasswd.decrypt(cpass)
        expect(pass).to eq('')
      end
    end
  end
end
