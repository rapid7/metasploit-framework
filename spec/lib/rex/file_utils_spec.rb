require 'rex/file'

describe Rex::FileUtils do
	context "Class methods" do

		context ".normalize_win_path" do
			it "should convert an absolute path as an array into Windows format" do
				described_class.normalize_win_path('C:\\', 'hello', 'world').should eq("C:\\hello\\world")
			end

			it "should convert an absolute path as a string into Windows format" do
				described_class.normalize_win_path('C:\\hello\\world').should eq("C:\\hello\\world")
			end

			it "should convert a relative path" do
				described_class.normalize_win_path('/', 'test', 'me').should eq("\\test\\me")
				described_class.normalize_win_path('\\temp').should eq("\\temp")
				described_class.normalize_win_path('temp').should eq("temp")
			end

			it "should keep the trailing slash if exists" do
				described_class.normalize_win_path('/', 'test', 'me\\').should eq("\\test\\me\\")
				described_class.normalize_win_path('\\temp\\').should eq("\\temp\\")
			end

			it "should convert a path without reserved characters" do
				described_class.normalize_win_path('C:\\', 'Windows:').should eq("C:\\Windows")
				described_class.normalize_win_path('C:\\Windows???\\test').should eq("C:\\Windows\\test")
			end

			it "should convert a path without double slashes" do
				described_class.normalize_win_path('C:\\\\\\', 'Windows').should eq("C:\\Windows")
				described_class.normalize_win_path('C:\\\\\\Hello World\\\\whatever.txt').should eq("C:\\Hello World\\whatever.txt")
				described_class.normalize_win_path('C:\\\\').should eq("C:\\")
				described_class.normalize_win_path('\\test\\\\test\\\\').should eq("\\test\\test\\")
			end
		end

		context ".normalize_unix_path" do
			it "should convert an absolute path as an array into Unix format" do
				described_class.normalize_unix_path('/etc', '/passwd').should eq("/etc/passwd")
			end

			it "should convert an absolute path as a string into Unix format" do
				described_class.normalize_unix_path('/etc/passwd').should eq('/etc/passwd')
			end

			it "should still give me a trailing slash if I have it" do
				described_class.normalize_unix_path('/etc/folder/').should eq("/etc/folder/")
			end

			it "should convert a path without double slashes" do
				described_class.normalize_unix_path('//etc////passwd').should eq("/etc/passwd")
				described_class.normalize_unix_path('/etc////', 'passwd').should eq('/etc/passwd')
			end
		end

	end
end

