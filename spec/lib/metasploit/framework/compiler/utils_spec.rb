require 'spec_helper'
require 'metasm'
require 'metasploit/framework/compiler/windows'

RSpec.describe Metasploit::Framework::Compiler::Utils do
  describe '#self.normalize_code' do
    let(:c_template) {
      %Q|#include <Windows.h>
      int main(void) {
        MessageBox(NULL, "Hello World", "Test", MB_OK);
        return 0;
      }
      |
    }

    it 'returns the raw source code' do
      headers = Metasploit::Framework::Compiler::Headers::Windows.new
      source_code = Metasploit::Framework::Compiler::Utils.normalize_code(c_template, headers)
      expect(source_code).to include('#define APIENTRY WINAPI')
    end
  end
end