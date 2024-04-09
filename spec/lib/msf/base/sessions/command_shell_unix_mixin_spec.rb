RSpec.describe Msf::Sessions::CommandShellUnix::Mixin do
  let(:obj) do
    o = Object.new
    o.extend(described_class)
    
    o
  end

  describe 'to_cmd processing' do
    it 'should not do anything for simple args' do
      expect(obj.to_cmd('./test', [])).to eq('./test')
      expect(obj.to_cmd('sh', [])).to eq('sh')
      expect(obj.to_cmd('./test', ['basic','args'])).to eq('./test basic args')
    end

    it 'should quote spaces' do
      expect(obj.to_cmd('/home/user/some folder/some program', [])).to eq("'/home/user/some folder/some program'")
      expect(obj.to_cmd('./test', ['with space'])).to eq("./test 'with space'")
    end

    it 'should quote logical operators' do
      expect(obj.to_cmd('./test', ['&&', 'echo', 'words'])).to eq("./test '&&' echo words")
      expect(obj.to_cmd('./test', ['||', 'echo', 'words'])).to eq("./test '||' echo words")
      expect(obj.to_cmd('./test', ['&echo', 'words'])).to eq("./test '&echo' words")
      expect(obj.to_cmd('./test', ['run&echo', 'words'])).to eq("./test 'run&echo' words")
    end

    it 'should escape single quotes' do
      expect(obj.to_cmd('./test', ["it's"])).to eq("./test it\\'s")
      expect(obj.to_cmd('./test', ["it's a param"])).to eq("./test 'it\\'s a param'")
    end

    it 'should quote redirectors' do
      expect(obj.to_cmd('./test', ['>', 'out.txt'])).to eq("./test '>' out.txt")
      expect(obj.to_cmd('./test', ['<', 'in.txt'])).to eq("./test '<' in.txt")
    end

    it 'should not expand env vars' do
      expect(obj.to_cmd('./test', ['$PATH'])).to eq("./test '$PATH'")
      expect(obj.to_cmd('./test', ['env', 'var', 'is', '$PATH'])).to eq("./test env var is '$PATH'")
    end
  end
end