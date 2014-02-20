#!/usr/bin/env ruby

$VERBOSE = true

class TestFiles
  RANDOM_ASCII_FILE1  = "data/generated/randomAscii1.txt"
  RANDOM_ASCII_FILE2  = "data/generated/randomAscii2.txt"
  RANDOM_ASCII_FILE3  = "data/generated/randomAscii3.txt"
  RANDOM_BINARY_FILE1 = "data/generated/randomBinary1.bin"
  RANDOM_BINARY_FILE2 = "data/generated/randomBinary2.bin"

  EMPTY_TEST_DIR      = "data/generated/emptytestdir"

  ASCII_TEST_FILES  = [ RANDOM_ASCII_FILE1, RANDOM_ASCII_FILE2, RANDOM_ASCII_FILE3 ] 
  BINARY_TEST_FILES = [ RANDOM_BINARY_FILE1, RANDOM_BINARY_FILE2 ]
  TEST_DIRECTORIES  = [ EMPTY_TEST_DIR ]
  TEST_FILES        = [ ASCII_TEST_FILES, BINARY_TEST_FILES, EMPTY_TEST_DIR ].flatten!

  def TestFiles.create_test_files(recreate)
    if (recreate || 
  ! (TEST_FILES.inject(true) { |accum, element| accum && File.exists?(element) }))
      
      Dir.mkdir "data/generated" rescue Errno::EEXIST

      ASCII_TEST_FILES.each_with_index { 
  |filename, index| 
  create_random_ascii(filename, 1E4 * (index+1))
      }
      
      BINARY_TEST_FILES.each_with_index { 
  |filename, index| 
  create_random_binary(filename, 1E4 * (index+1))
      }

      ensure_dir(EMPTY_TEST_DIR)
    end
  end

  private
  def TestFiles.create_random_ascii(filename, size)
    File.open(filename, "wb") {
      |file|
      while (file.tell < size)
  file << rand
      end
    }
  end

  def TestFiles.create_random_binary(filename, size)
    File.open(filename, "wb") {
      |file|
      while (file.tell < size)
  file << [rand].pack("V")
      end
    }
  end

  def TestFiles.ensure_dir(name) 
    if File.exists?(name)
      return if File.stat(name).directory?
      File.delete(name)
    end
    Dir.mkdir(name)
  end

end



# For representation and creation of
# test data
class TestZipFile
  attr_accessor :zip_name, :entry_names, :comment

  def initialize(zip_name, entry_names, comment = "")
    @zip_name=zip_name
    @entry_names=entry_names
  if "".respond_to? :force_encoding
    @entry_names.each {|name| name.force_encoding("ASCII-8BIT")}
  end
    @comment = comment
  end

  def TestZipFile.create_test_zips(recreate)
    files = Dir.entries("data/generated")
    if (recreate || 
      ! (files.index(File.basename(TEST_ZIP1.zip_name)) &&
         files.index(File.basename(TEST_ZIP2.zip_name)) &&
         files.index(File.basename(TEST_ZIP3.zip_name)) &&
         files.index(File.basename(TEST_ZIP4.zip_name)) &&
         files.index("empty.txt")      &&
         files.index("empty_chmod640.txt")      &&
         files.index("short.txt")      &&
         files.index("longAscii.txt")  &&
         files.index("longBinary.bin") ))
      raise "failed to create test zip '#{TEST_ZIP1.zip_name}'" unless 
  system("zip #{TEST_ZIP1.zip_name} data/file2.txt")
      raise "failed to remove entry from '#{TEST_ZIP1.zip_name}'" unless 
  system("zip #{TEST_ZIP1.zip_name} -d data/file2.txt")
      
      File.open("data/generated/empty.txt", "w") {}
      File.open("data/generated/empty_chmod640.txt", "w") { |f| f.chmod(0640) }
      
      File.open("data/generated/short.txt", "w") { |file| file << "ABCDEF" }
      ziptestTxt=""
      File.open("data/file2.txt") { |file| ziptestTxt=file.read }
      File.open("data/generated/longAscii.txt", "w") {
  |file|
  while (file.tell < 1E5)
    file << ziptestTxt
  end
      }
      
      testBinaryPattern=""
      File.open("data/generated/empty.zip") { |file| testBinaryPattern=file.read }
      testBinaryPattern *= 4
      
      File.open("data/generated/longBinary.bin", "wb") {
  |file|
  while (file.tell < 3E5)
    file << testBinaryPattern << rand << "\0"
  end
      }
      raise "failed to create test zip '#{TEST_ZIP2.zip_name}'" unless 
  system("zip #{TEST_ZIP2.zip_name} #{TEST_ZIP2.entry_names.join(' ')}")

      # without bash system interprets everything after echo as parameters to
      # echo including | zip -z ...
      raise "failed to add comment to test zip '#{TEST_ZIP2.zip_name}'" unless 
  system("bash -c \"echo #{TEST_ZIP2.comment} | zip -z #{TEST_ZIP2.zip_name}\"")

      raise "failed to create test zip '#{TEST_ZIP3.zip_name}'" unless 
  system("zip #{TEST_ZIP3.zip_name} #{TEST_ZIP3.entry_names.join(' ')}")

      raise "failed to create test zip '#{TEST_ZIP4.zip_name}'" unless 
  system("zip #{TEST_ZIP4.zip_name} #{TEST_ZIP4.entry_names.join(' ')}")
    end
  rescue 
    raise $!.to_s + 
      "\n\nziptest.rb requires the Info-ZIP program 'zip' in the path\n" +
      "to create test data. If you don't have it you can download\n"   +
      "the necessary test files at http://sf.net/projects/rubyzip."
  end

  TEST_ZIP1 = TestZipFile.new("data/generated/empty.zip", [])
  TEST_ZIP2 = TestZipFile.new("data/generated/5entry.zip", %w{ data/generated/longAscii.txt data/generated/empty.txt data/generated/empty_chmod640.txt data/generated/short.txt data/generated/longBinary.bin}, 
            "my zip comment")
  TEST_ZIP3 = TestZipFile.new("data/generated/test1.zip", %w{ data/file1.txt })
  TEST_ZIP4 = TestZipFile.new("data/generated/zipWithDir.zip", [ "data/file1.txt", 
        TestFiles::EMPTY_TEST_DIR])
end


END {
  TestFiles::create_test_files(ARGV.index("recreate") != nil || 
           ARGV.index("recreateonly") != nil)
  TestZipFile::create_test_zips(ARGV.index("recreate") != nil || 
            ARGV.index("recreateonly") != nil)
  exit if ARGV.index("recreateonly") != nil
}
