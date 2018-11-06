#!/usr/bin/env ruby

$VERBOSE = true

class TestFiles
  RANDOM_ASCII_FILE1  = 'test/data/generated/randomAscii1.txt'
  RANDOM_ASCII_FILE2  = 'test/data/generated/randomAscii2.txt'
  RANDOM_ASCII_FILE3  = 'test/data/generated/randomAscii3.txt'
  RANDOM_BINARY_FILE1 = 'test/data/generated/randomBinary1.bin'
  RANDOM_BINARY_FILE2 = 'test/data/generated/randomBinary2.bin'

  NULL_FILE = 'test/data/generated/null.zip' # Zero length, so not a zip file.

  EMPTY_TEST_DIR = 'test/data/generated/emptytestdir'

  ASCII_TEST_FILES = [RANDOM_ASCII_FILE1, RANDOM_ASCII_FILE2, RANDOM_ASCII_FILE3]
  BINARY_TEST_FILES = [RANDOM_BINARY_FILE1, RANDOM_BINARY_FILE2]
  TEST_DIRECTORIES = [EMPTY_TEST_DIR]
  TEST_FILES = [ASCII_TEST_FILES, BINARY_TEST_FILES, EMPTY_TEST_DIR].flatten!

  class << self
    def create_test_files
      Dir.mkdir 'test/data/generated' unless Dir.exist?('test/data/generated')

      ASCII_TEST_FILES.each_with_index do |filename, index|
        create_random_ascii(filename, 1E4 * (index + 1))
      end

      BINARY_TEST_FILES.each_with_index do |filename, index|
        create_random_binary(filename, 1E4 * (index + 1))
      end

      system("touch #{NULL_FILE}")

      ensure_dir(EMPTY_TEST_DIR)
    end

    private

    def create_random_ascii(filename, size)
      File.open(filename, 'wb') do |file|
        file << rand while file.tell < size
      end
    end

    def create_random_binary(filename, size)
      File.open(filename, 'wb') do |file|
        file << [rand].pack('V') while file.tell < size
      end
    end

    def ensure_dir(name)
      if File.exist?(name)
        return if File.stat(name).directory?
        File.delete(name)
      end
      Dir.mkdir(name)
    end
  end
end

# For representation and creation of
# test data
class TestZipFile
  attr_accessor :zip_name, :entry_names, :comment

  def initialize(zip_name, entry_names, comment = '')
    @zip_name = zip_name
    @entry_names = entry_names
    @comment = comment
  end

  def self.create_test_zips
    raise "failed to create test zip '#{TEST_ZIP1.zip_name}'" unless system("/usr/bin/zip -q #{TEST_ZIP1.zip_name} test/data/file2.txt")
    raise "failed to remove entry from '#{TEST_ZIP1.zip_name}'" unless system("/usr/bin/zip -q #{TEST_ZIP1.zip_name} -d test/data/file2.txt")

    File.open('test/data/generated/empty.txt', 'w') {}
    File.open('test/data/generated/empty_chmod640.txt', 'w') {}
    ::File.chmod(0o640, 'test/data/generated/empty_chmod640.txt')

    File.open('test/data/generated/short.txt', 'w') { |file| file << 'ABCDEF' }
    ziptestTxt = ''
    File.open('test/data/file2.txt') { |file| ziptestTxt = file.read }
    File.open('test/data/generated/longAscii.txt', 'w') do |file|
      file << ziptestTxt while file.tell < 1E5
    end

    testBinaryPattern = ''
    File.open('test/data/generated/empty.zip') { |file| testBinaryPattern = file.read }
    testBinaryPattern *= 4

    File.open('test/data/generated/longBinary.bin', 'wb') do |file|
      file << testBinaryPattern << rand << "\0" while file.tell < 6E5
    end

    raise "failed to create test zip '#{TEST_ZIP2.zip_name}'" unless system("/usr/bin/zip -q #{TEST_ZIP2.zip_name} #{TEST_ZIP2.entry_names.join(' ')}")

    if RUBY_PLATFORM =~ /mswin|mingw|cygwin/
      raise "failed to add comment to test zip '#{TEST_ZIP2.zip_name}'" unless system("echo #{TEST_ZIP2.comment}| /usr/bin/zip -zq #{TEST_ZIP2.zip_name}\"")
    else
      # without bash system interprets everything after echo as parameters to
      # echo including | zip -z ...
      raise "failed to add comment to test zip '#{TEST_ZIP2.zip_name}'" unless system("bash -c \"echo #{TEST_ZIP2.comment} | /usr/bin/zip -zq #{TEST_ZIP2.zip_name}\"")
    end

    raise "failed to create test zip '#{TEST_ZIP3.zip_name}'" unless system("/usr/bin/zip -q #{TEST_ZIP3.zip_name} #{TEST_ZIP3.entry_names.join(' ')}")

    raise "failed to create test zip '#{TEST_ZIP4.zip_name}'" unless system("/usr/bin/zip -q #{TEST_ZIP4.zip_name} #{TEST_ZIP4.entry_names.join(' ')}")
  rescue
    # If there are any Windows developers wanting to use a command line zip.exe
    # to help create the following files, there's a free one available from
    # http://stahlworks.com/dev/index.php?tool=zipunzip
    # that works with the above code
    raise $!.to_s +
          "\n\nziptest.rb requires the Info-ZIP program 'zip' in the path\n" \
          "to create test data. If you don't have it you can download\n" \
          'the necessary test files at http://sf.net/projects/rubyzip.'
  end

  TEST_ZIP1 = TestZipFile.new('test/data/generated/empty.zip', [])
  TEST_ZIP2 = TestZipFile.new('test/data/generated/5entry.zip', %w[test/data/generated/longAscii.txt test/data/generated/empty.txt test/data/generated/empty_chmod640.txt test/data/generated/short.txt test/data/generated/longBinary.bin],
                              'my zip comment')
  TEST_ZIP3 = TestZipFile.new('test/data/generated/test1.zip', %w[test/data/file1.txt])
  TEST_ZIP4 = TestZipFile.new('test/data/generated/zipWithDir.zip', ['test/data/file1.txt',
                                                                     TestFiles::EMPTY_TEST_DIR])
end
