RSpec.describe Msf::Sessions::CommandShellWindows do

  describe 'to_cmd processing' do
    it 'should not do anything for simple args' do
      expect(described_class.to_cmd(['test.exe'] + [])).to eq('test.exe')
      expect(described_class.to_cmd(['test.exe'] + ['basic','args'])).to eq('test.exe basic args')
    end

    it 'should quote spaces' do
      expect(described_class.to_cmd(['C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE'] + [])).to eq('"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"')
      expect(described_class.to_cmd(['test.exe'] + ['with space'])).to eq('test.exe "with space"')
    end

    it 'should escape logical operators' do
      expect(described_class.to_cmd(['test.exe'] + ['&&', 'echo', 'words'])).to eq('test.exe "&&" echo words')
      expect(described_class.to_cmd(['test.exe'] + ['||', 'echo', 'words'])).to eq('test.exe "||" echo words')
      expect(described_class.to_cmd(['test.exe'] + ['&echo', 'words'])).to eq('test.exe "&echo" words')
      expect(described_class.to_cmd(['test.exe'] + ['run&echo', 'words'])).to eq('test.exe "run&echo" words')
    end

    it 'should escape redirectors' do
      expect(described_class.to_cmd(['test.exe'] + ['>', 'out.txt'])).to eq('test.exe ">" out.txt')
      expect(described_class.to_cmd(['test.exe'] + ['<', 'in.txt'])).to eq('test.exe "<" in.txt')
    end

    it 'should escape carets' do
      expect(described_class.to_cmd(['test.exe'] + ['with^caret'])).to eq('test.exe "with^caret"')
      expect(described_class.to_cmd(['test.exe'] + ['with^^carets'])).to eq('test.exe "with^^carets"')
    end

    it 'should not expand env vars' do
      expect(described_class.to_cmd(['test.exe'] + ['%temp%'])).to eq('test.exe ^%temp^%')
      expect(described_class.to_cmd(['test.exe'] + ['env', 'var', 'is', '%temp%'])).to eq('test.exe env var is ^%temp^%')
    end

    it 'should handle the weird backslash escaping behaviour in front of quotes' do
      expect(described_class.to_cmd(['test.exe'] + ['quote\\\\"'])).to eq('test.exe "quote\\\\\\\\""')
      expect(described_class.to_cmd(['test.exe'] + ['will be quoted\\\\'])).to eq('test.exe "will be quoted\\\\\\\\"')
      expect(described_class.to_cmd(['test.exe'] + ['will be quoted\\\\ '])).to eq('test.exe "will be quoted\\\\ "') # Should not be doubled up
      expect(described_class.to_cmd(['test.exe'] + ['"test"', 'test\\"', 'test\\\\"', 'test words\\\\\\\\', 'test words\\\\\\', '\\\\'])).to eq('test.exe """test""" "test\\\\"" "test\\\\\\\\"" "test words\\\\\\\\\\\\\\\\" "test words\\\\\\\\\\\\" \\\\')
    end

    it 'should handle combinations of quoting and percent-escaping' do
      expect(described_class.to_cmd(['test.exe'] + ['env var is %temp%'])).to eq('test.exe "env var is "^%temp^%')
      expect(described_class.to_cmd(['test.exe'] + ['env var is %temp%, yes, %TEMP%'])).to eq('test.exe "env var is "^%temp^%", yes, "^%TEMP^%')
      expect(described_class.to_cmd(['test.exe'] + ['%temp%found at the start shouldn\'t %temp% be quoted'])).to eq('test.exe ^%temp^%"found at the start shouldn\'t "^%temp^%" be quoted"')
    end

    it 'should handle single percents' do
      expect(described_class.to_cmd(['test.exe'] + ['%single percent'])).to eq('test.exe ^%"single percent"')
      expect(described_class.to_cmd(['test.exe'] + ['100%'])).to eq('test.exe 100^%')
    end

    it 'should handle empty args' do
      expect(described_class.to_cmd(['test.exe'] + [''])).to eq('test.exe ""')
      expect(described_class.to_cmd(['test.exe'] + ['', ''])).to eq('test.exe "" ""')
    end
  end

  describe 'argv_to_commandline processing' do
    it 'should not do anything for simple args' do
      expect(described_class.argv_to_commandline([])).to eq('')
      expect(described_class.argv_to_commandline(['basic','args'])).to eq('basic args')
      expect(described_class.argv_to_commandline(['!@#$%^&*(){}><.,\''])).to eq('!@#$%^&*(){}><.,\'')
    end

    it 'should quote space characters' do
      expect(described_class.argv_to_commandline([])).to eq('')
      expect(described_class.argv_to_commandline(['basic','args'])).to eq('basic args')
    end

    it 'should escape double-quote characters' do
      expect(described_class.argv_to_commandline(['"one','"two"'])).to eq('\\"one \\"two\\"')
      expect(described_class.argv_to_commandline(['"one "two"'])).to eq('"\\"one \\"two\\""')
    end

    it 'should handle the weird backslash escaping behaviour in front of quotes' do
      expect(described_class.argv_to_commandline(['\\\\"'])).to eq('\\\\\\\\\\"')
      expect(described_class.argv_to_commandline(['space \\\\'])).to eq('"space \\\\\\\\"')
      expect(described_class.argv_to_commandline(['"test"', 'test\\"', 'test\\\\"', 'test words\\\\\\\\', 'test words\\\\\\', '\\\\'])).to eq('\"test\" test\\\\\\" test\\\\\\\\\\" "test words\\\\\\\\\\\\\\\\" "test words\\\\\\\\\\\\" \\\\')
    end

    it 'should handle empty args' do
      expect(described_class.argv_to_commandline([''])).to eq('""')
      expect(described_class.argv_to_commandline(['', ''])).to eq('"" ""')
    end
  end
end