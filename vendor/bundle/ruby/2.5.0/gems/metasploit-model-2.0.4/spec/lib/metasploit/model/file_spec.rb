RSpec.describe Metasploit::Model::File do
  unless RUBY_PLATFORM =~ /java/ && Gem::Version.new(JRUBY_VERSION) < Gem::Version.new('1.7.14')
    it 'aliases ::File' do
      expect(described_class).to equal(::File)
    end
  end

  context 'realpath' do
    let(:real_basename) do
      'real'
    end

    let(:real_pathname) do
      Metasploit::Model::Spec.temporary_pathname.join(real_basename)
    end

    let(:symlink_basename) do
      'symlink'
    end

    let(:symlink_pathname) do
      Metasploit::Model::Spec.temporary_pathname.join(symlink_basename)
    end

    before(:example) do
      real_pathname.mkpath

      Dir.chdir(Metasploit::Model::Spec.temporary_pathname.to_path) do
        File.symlink(real_basename, 'symlink')
      end
    end

    def realpath
      described_class.realpath(symlink_pathname.to_path)
    end

    if RUBY_PLATFORM =~ /java/ && Gem::Version.new(JRUBY_VERSION) < Gem::Version.new('1.7.14')
      it 'should be necessary because File.realpath does not resolve symlinks' do
        expect(File.realpath(symlink_pathname.to_path)).not_to eq(real_pathname.to_path)
      end
    end

    it 'should resolve symlink to real (canonical) path' do
      expect(realpath).to eq(real_pathname.to_path)
    end
  end
end