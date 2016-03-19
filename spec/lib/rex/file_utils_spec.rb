require 'rex/file'

RSpec.describe Rex::FileUtils do
  context "Class methods" do

    context ".normalize_win_path" do
      it "should convert an absolute path as an array into Windows format" do
        expect(described_class.normalize_win_path('C:\\', 'hello', 'world')).to eq("C:\\hello\\world")
      end

      it "should convert an absolute path as a string into Windows format" do
        expect(described_class.normalize_win_path('C:\\hello\\world')).to eq("C:\\hello\\world")
      end

      it "should convert a relative path" do
        expect(described_class.normalize_win_path('/', 'test', 'me')).to eq("\\test\\me")
        expect(described_class.normalize_win_path('\\temp')).to eq("\\temp")
        expect(described_class.normalize_win_path('temp')).to eq("temp")
      end

      it "should keep the trailing slash if exists" do
        expect(described_class.normalize_win_path('/', 'test', 'me\\')).to eq("\\test\\me\\")
        expect(described_class.normalize_win_path('\\temp\\')).to eq("\\temp\\")
      end

      it "should convert a path without reserved characters" do
        expect(described_class.normalize_win_path('C:\\', 'Windows:')).to eq("C:\\Windows")
        expect(described_class.normalize_win_path('C:\\Windows???\\test')).to eq("C:\\Windows\\test")
      end

      it "should convert a path without double slashes" do
        expect(described_class.normalize_win_path('C:\\\\\\', 'Windows')).to eq("C:\\Windows")
        expect(described_class.normalize_win_path('C:\\\\\\Hello World\\\\whatever.txt')).to eq("C:\\Hello World\\whatever.txt")
        expect(described_class.normalize_win_path('C:\\\\')).to eq("C:\\")
        expect(described_class.normalize_win_path('\\test\\\\test\\\\')).to eq("\\test\\test\\")
      end
    end

    context ".normalize_unix_path" do
      it "should convert an absolute path as an array into Unix format" do
        expect(described_class.normalize_unix_path('/etc', '/passwd')).to eq("/etc/passwd")
      end

      it "should convert an absolute path as a string into Unix format" do
        expect(described_class.normalize_unix_path('/etc/passwd')).to eq('/etc/passwd')
      end

      it "should still give me a trailing slash if I have it" do
        expect(described_class.normalize_unix_path('/etc/folder/')).to eq("/etc/folder/")
      end

      it "should convert a path without double slashes" do
        expect(described_class.normalize_unix_path('//etc////passwd')).to eq("/etc/passwd")
        expect(described_class.normalize_unix_path('/etc////', 'passwd')).to eq('/etc/passwd')
      end
    end

  end
end

