require 'test_helper'
require 'fileutils'
require_relative '../../samples/example_recursive'

class ExampleRecursiveTest < MiniTest::Test
  DIRECTORY_TO_ZIP  = 'test/data/globTest'
  OUTPUT_DIRECTORY  = 'test/data/example_recursive.zip'
  TEMP_DIRECTORY    = 'test/data/tmp'

  def setup
    @generator = ::ZipFileGenerator.new(DIRECTORY_TO_ZIP, OUTPUT_DIRECTORY)
  end

  def teardown
    FileUtils.rm_rf TEMP_DIRECTORY
    FileUtils.rm_f OUTPUT_DIRECTORY
  end

  def test_write
    @generator.write
    unzip
    assert_equal Dir.entries(DIRECTORY_TO_ZIP).sort, Dir.entries(TEMP_DIRECTORY).sort
  end

  private

  def unzip(file = OUTPUT_DIRECTORY)
    Zip::File.open(file) do |zip_file|
      zip_file.each do |f|
        file_path = File.join(TEMP_DIRECTORY, f.name)
        FileUtils.mkdir_p(File.dirname(file_path))

        zip_file.extract(f, file_path) unless File.exist?(file_path)
      end
    end
  end
end
