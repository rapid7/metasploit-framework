if ENV['FULL_ZIP64_TEST']
  require 'minitest/autorun'
  require 'minitest/unit'
  require 'fileutils'
  require 'zip'

  # test zip64 support for real, by actually exceeding the 32-bit size/offset limits
  # this test does not, of course, run with the normal unit tests! ;)

  class Zip64FullTest < MiniTest::Test
    def teardown
      ::Zip.reset!
    end

    def prepare_test_file(test_filename)
      ::File.delete(test_filename) if ::File.exist?(test_filename)
      test_filename
    end

    def test_large_zip_file
      ::Zip.write_zip64_support = true
      first_text = 'starting out small'
      last_text = 'this tests files starting after 4GB in the archive'
      test_filename = prepare_test_file('huge.zip')
      ::Zip::OutputStream.open(test_filename) do |io|
        io.put_next_entry('first_file.txt')
        io.write(first_text)

        # write just over 4GB (stored, so the zip file exceeds 4GB)
        buf = 'blah' * 16_384
        io.put_next_entry('huge_file', nil, nil, ::Zip::Entry::STORED)
        65_537.times { io.write(buf) }

        io.put_next_entry('last_file.txt')
        io.write(last_text)
      end

      ::Zip::File.open(test_filename) do |zf|
        assert_equal %w[first_file.txt huge_file last_file.txt], zf.entries.map(&:name)
        assert_equal first_text, zf.read('first_file.txt')
        assert_equal last_text, zf.read('last_file.txt')
      end

      # note: if this fails, be sure you have UnZip version 6.0 or newer
      # as this is the first version to support zip64 extensions
      # but some OSes (*cough* OSX) still bundle a 5.xx release
      assert system("unzip -tqq #{test_filename}"), 'third-party zip validation failed'
    end
  end

end
