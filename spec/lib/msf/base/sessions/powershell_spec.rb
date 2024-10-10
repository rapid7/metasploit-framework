RSpec.describe Msf::Sessions::PowerShell do
  describe 'to_cmd processing' do
    it 'should not do anything for simple args' do
      expect(described_class.to_cmd([".\\test.exe"] + ['abc', '123'])).to eq(".\\test.exe abc 123")
      expect(described_class.to_cmd(["C:\\SysinternalsSuite\\procexp.exe"] + [])).to eq("C:\\SysinternalsSuite\\procexp.exe")
    end

    it 'should double single-quotes' do
      expect(described_class.to_cmd([".\\test.exe"] + ["'abc'"])).to eq(".\\test.exe '''abc'''")
    end

    it 'should escape less than' do
      expect(described_class.to_cmd([".\\test.exe"] + ["'abc'", '>', 'out.txt'])).to eq(".\\test.exe '''abc''' '>' out.txt")
    end

    it 'should escape other special chars' do
      expect(described_class.to_cmd([".\\test.exe"] + ["'abc'", '<', '(', ')', '$test', '`words`', 'abc,def'])).to eq(".\\test.exe '''abc''' '<' '(' ')' '$test' '`words`' 'abc,def'")
    end

    it 'should backslash escape double-quotes' do
      expect(described_class.to_cmd([".\\test.exe"] + ['"abc'])).to eq(".\\test.exe '\\\"abc'")
    end

    it 'should correctly backslash escape backslashes and double-quotes' do
      expect(described_class.to_cmd([".\\test.exe"] + ['\\"abc'])).to eq(".\\test.exe '\\\\\\\"abc'")
      expect(described_class.to_cmd([".\\test.exe"] + ['\\\\"abc'])).to eq(".\\test.exe '\\\\\\\\\\\"abc'")
      expect(described_class.to_cmd([".\\test.exe"] + ['\\\\"ab\\\\c'])).to eq(".\\test.exe '\\\\\\\\\\\"ab\\\\c'")
    end

    it 'should quote the executable and add the call operator' do
      expect(described_class.to_cmd([".\\test$.exe"] + ['abc'])).to eq("& '.\\test$.exe' abc")
      expect(described_class.to_cmd([".\\test'.exe"] + ['abc'])).to eq("& '.\\test''.exe' abc")
      expect(described_class.to_cmd(["C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"] + [])).to eq("& 'C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE'")
    end

    it 'should not expand environment variables' do
      expect(described_class.to_cmd([".\\test.exe"] + ['$env:path'])).to eq(".\\test.exe '$env:path'")
    end

    it 'should not respect PowerShell Magic' do
      expect(described_class.to_cmd([".\\test.exe"] + ['--%', 'not', '$parsed'])).to eq(".\\test.exe '--%' not '$parsed'")
    end
      
    it 'should not split comma args' do
      expect(described_class.to_cmd([".\\test.exe"] + ['arg1,notarg2'])).to eq(".\\test.exe 'arg1,notarg2'")
    end

    it 'should handle empty strings' do
      expect(described_class.to_cmd([".\\test.exe"] + ['', 'a', '', 'b'])).to eq(".\\test.exe '\"\"' a '\"\"' b")
    end
  end
end