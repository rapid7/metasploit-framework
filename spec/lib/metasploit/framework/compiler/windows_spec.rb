require 'spec_helper'
require 'metasploit/framework/compiler/windows'

RSpec.describe Metasploit::Framework::Compiler::Windows do
  describe '#self.compile_c' do
    let(:c_template) {
      %Q|#include <Windows.h>

      int main(void) {
        MessageBox(NULL, "Hello World", "Test", MB_OK);
        return 0;
      }
      |
    }

    it 'returns an EXE binary' do
      bin = Metasploit::Framework::Compiler::Windows.compile_c(c_template)
      magic = bin[0, 2]
      expect(magic).to eq('MZ')
    end
  end
end