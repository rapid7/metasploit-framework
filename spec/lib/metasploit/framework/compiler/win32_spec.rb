require 'spec_helper'
require 'metasploit/framework/compiler/win32'

RSpec.describe Metasploit::Framework::Compiler::Win32 do
  describe '#self.compile' do
    let(:c_template) {
      %Q|#include <Windows.h>

      int main(void) {
        MessageBox(NULL, "Hello World", "Test", MB_OK);
        return 0;
      }
      |
    }

    it 'returns an EXE binary' do
      bin = Metasploit::Framework::Compiler::Win32.compile(c_template)
      magic = bin[0, 2]
      expect(magic).to eq('MZ')
    end
  end
end