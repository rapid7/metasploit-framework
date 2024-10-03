RSpec.describe Msf::Sessions::CommandShellUnix do
  describe 'to_cmd processing' do
    it 'should not do anything for simple args' do
      expect(described_class.to_cmd(['./test'] + [])).to eq('./test')
      expect(described_class.to_cmd(['sh'] + [])).to eq('sh')
      expect(described_class.to_cmd(['./test'] + ['basic','args'])).to eq('./test basic args')
      expect(described_class.to_cmd(['basic','args'])).to eq('basic args')
    end

    it 'should escape spaces' do
      expect(described_class.to_cmd(['/home/user/some folder/some program'] + [])).to eq("'/home/user/some folder/some program'")
      expect(described_class.to_cmd(['./test'] + ['with space'])).to eq("./test 'with space'")
    end

    it 'should escape logical operators' do
      expect(described_class.to_cmd(['./test'] + ['&&', 'echo', 'words'])).to eq("./test '&&' echo words")
      expect(described_class.to_cmd(['./test'] + ['||', 'echo', 'words'])).to eq("./test '||' echo words")
      expect(described_class.to_cmd(['./test'] + ['&echo', 'words'])).to eq("./test '&echo' words")
      expect(described_class.to_cmd(['./test'] + ['run&echo', 'words'])).to eq("./test 'run&echo' words")
    end

    it 'should quote if single quotes are present' do
      expect(described_class.to_cmd(['./test'] + ["it's"])).to eq("./test it\\'s")
      expect(described_class.to_cmd(['./test'] + ["it's a param"])).to eq("./test it\\''s a param'")
    end

    it 'should escape redirectors' do
      expect(described_class.to_cmd(['./test'] + ['>', 'out.txt'])).to eq("./test '>' out.txt")
      expect(described_class.to_cmd(['./test'] + ['<', 'in.txt'])).to eq("./test '<' in.txt")
    end

    it 'should not expand env vars' do
      expect(described_class.to_cmd(['./test'] + ['$PATH'])).to eq("./test '$PATH'")
      expect(described_class.to_cmd(['./test'] + ["it's $PATH"])).to eq("./test it\\''s $PATH'")
      expect(described_class.to_cmd(['./test'] + ["\"$PATH\""])).to eq("./test '\"$PATH\"'")
      expect(described_class.to_cmd(['./test'] + ["it's \"$PATH\""])).to eq("./test it\\''s \"$PATH\"'")
    end
  end
end