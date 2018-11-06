require 'test_helper'

class EncryptionTest < MiniTest::Test
  ENCRYPT_ZIP_TEST_FILE = 'test/data/zipWithEncryption.zip'
  INPUT_FILE1 = 'test/data/file1.txt'

  def setup
    @default_compression = Zip.default_compression
    Zip.default_compression = ::Zlib::DEFAULT_COMPRESSION
  end

  def teardown
    Zip.default_compression = @default_compression
  end

  def test_encrypt
    test_file = open(ENCRYPT_ZIP_TEST_FILE, 'rb').read

    @rand = [250, 143, 107, 13, 143, 22, 155, 75, 228, 150, 12]
    @output = ::Zip::DOSTime.stub(:now, ::Zip::DOSTime.new(2014, 12, 17, 15, 56, 24)) do
      Random.stub(:rand, ->(_range) { @rand.shift }) do
        Zip::OutputStream.write_buffer(::StringIO.new(''), Zip::TraditionalEncrypter.new('password')) do |zos|
          zos.put_next_entry('file1.txt')
          zos.write open(INPUT_FILE1).read
        end.string
      end
    end

    @output.unpack('C*').each_with_index do |c, i|
      assert_equal test_file[i].ord, c
    end
  end

  def test_decrypt
    Zip::InputStream.open(ENCRYPT_ZIP_TEST_FILE, 0, Zip::TraditionalDecrypter.new('password')) do |zis|
      entry = zis.get_next_entry
      assert_equal 'file1.txt', entry.name
      assert_equal 1327, entry.size
      assert_equal open(INPUT_FILE1, 'r').read, zis.read
    end
  end
end
