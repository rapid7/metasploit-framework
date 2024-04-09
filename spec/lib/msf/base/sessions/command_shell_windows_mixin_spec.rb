RSpec.describe Msf::Sessions::CommandShellWindows::Mixin do
  let(:obj) do
    o = Object.new
    o.extend(described_class)
    
    o
  end

  describe 'to_cmd processing' do
    it 'should not do anything for simple args' do
      expect(obj.to_cmd('test.exe', [])).to eq('test.exe')
      expect(obj.to_cmd('test.exe', ['basic','args'])).to eq('test.exe basic args')
    end

    it 'should quote spaces' do
      expect(obj.to_cmd('C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE', [])).to eq('"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"')
      expect(obj.to_cmd('test.exe', ['with space'])).to eq('test.exe "with space"')
    end

    it 'should escape logical operators' do
      expect(obj.to_cmd('test.exe', ['&&', 'echo', 'words'])).to eq('test.exe "&&" echo words')
      expect(obj.to_cmd('test.exe', ['||', 'echo', 'words'])).to eq('test.exe "||" echo words')
      expect(obj.to_cmd('test.exe', ['&echo', 'words'])).to eq('test.exe "&echo" words')
      expect(obj.to_cmd('test.exe', ['run&echo', 'words'])).to eq('test.exe "run&echo" words')
    end

    it 'should escape redirectors' do
      expect(obj.to_cmd('test.exe', ['>', 'out.txt'])).to eq('test.exe ">" out.txt')
      expect(obj.to_cmd('test.exe', ['<', 'in.txt'])).to eq('test.exe "<" in.txt')
    end

    it 'should escape carets' do
      expect(obj.to_cmd('test.exe', ['with^caret'])).to eq('test.exe "with^caret"')
      expect(obj.to_cmd('test.exe', ['with^^carets'])).to eq('test.exe "with^^carets"')
    end

    it 'should not expand env vars' do
      expect(obj.to_cmd('test.exe', ['%temp%'])).to eq('test.exe ^%temp^%')
      expect(obj.to_cmd('test.exe', ['env', 'var', 'is', '%temp%'])).to eq('test.exe env var is ^%temp^%')
    end

    it 'should handle combinations of quoting and percent-escaping' do
      expect(obj.to_cmd('test.exe', ['env var is %temp%'])).to eq('test.exe "env var is "^%temp^%')
      expect(obj.to_cmd('test.exe', ['env var is %temp%, yes, %TEMP%'])).to eq('test.exe "env var is "^%temp^%", yes, "^%TEMP^%')
      expect(obj.to_cmd('test.exe', ['%temp%found at the start shouldn\'t %temp% be quoted'])).to eq('test.exe ^%temp^%"found at the start shouldn\'t "^%temp^%" be quoted"')
    end

    it 'should handle single percents' do
      expect(obj.to_cmd('test.exe', ['%single percent'])).to eq('test.exe ^%"single percent"')
      expect(obj.to_cmd('test.exe', ['100%'])).to eq('test.exe 100^%')
    end
  end
end