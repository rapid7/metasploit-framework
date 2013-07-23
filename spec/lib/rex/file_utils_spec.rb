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

			it "should convert a path without reserved characters" do
				described_class.normalize_win_path('C:\\', 'Windows:').should eq("C:\\Windows")
				described_class.normalize_win_path('C:\\Windows???\\test').should eq("C:\\Windows\\test")
			end

			it "should convert a path without double slashes" do
				described_class.normalize_win_path('C:\\\\\\', 'Windows').should eq("C:\\Windows")
				described_class.normalize_win_path('C:\\\\\\Hello World\\\\whatever.txt').should eq("C:\\Hello World\\whatever.txt")
				described_class.normalize_win_path('C:\\\\').should eq("C:\\")
			end

			it "should parse UNC path format as an array" do
				described_class.normalize_win_path('\\\\127.0.0.1', 'C$').should eq("\\\\127.0.0.1\\C$")
				described_class.normalize_win_path('\\\\127.0.0.1\\C$').should eq("\\\\127.0.0.1\\C$")
			end

			it "should parse a relative path in Windows format" do
				described_class.normalize_win_path('\\\\127.0.0.1', 'C$').should eq("\\\\127.0.0.1\\C$")
				described_class.normalize_win_path('\\\\127.0.0.1\\C$').should eq("\\\\127.0.0.1\\C$")
			end
		end

		context ".normalize_unix_path" do
			it "should convert an absolute path as an array into Unix format" do
				described_class.normalize_unix_path('/etc', '/passwd').should eq("/etc/passwd")
			end

			it "should convert an absolute path as a string into Windows format" do
				described_class.normalize_unix_path('/etc/passwd').should eq('/etc/passwd')
			end

			it "should convert a path without double slashes" do
				described_class.normalize_unix_path('//etc////passwd').should eq("/etc/passwd")
				described_class.normalize_unix_path('/etc////', 'passwd').should eq('/etc/passwd')
			end
		end

	end
end

