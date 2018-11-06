require 'test_helper'

class TraditionalEncrypterTest < MiniTest::Test
  def setup
    @mtime = ::Zip::DOSTime.new(2014, 12, 17, 15, 56, 24)
    @encrypter = ::Zip::TraditionalEncrypter.new('password')
  end

  def test_header_bytesize
    assert_equal 12, @encrypter.header_bytesize
  end

  def test_gp_flags
    assert_equal 9, @encrypter.gp_flags
  end

  def test_header
    @encrypter.reset!
    exepected = [239, 57, 234, 154, 246, 80, 83, 221, 74, 200, 121, 91].pack('C*')
    Random.stub(:rand, 1) do
      assert_equal exepected, @encrypter.header(@mtime)
    end
  end

  def test_encrypt
    @encrypter.reset!
    Random.stub(:rand, 1) { @encrypter.header(@mtime) }
    assert_raises(NoMethodError) { @encrypter.encrypt(nil) }
    assert_raises(NoMethodError) { @encrypter.encrypt(1) }
    assert_equal '', @encrypter.encrypt('')
    assert_equal [100, 218, 7, 114, 226, 82, 62, 93, 224, 62].pack('C*'), @encrypter.encrypt('a' * 10)
  end

  def test_reset!
    @encrypter.reset!
    Random.stub(:rand, 1) { @encrypter.header(@mtime) }
    [100, 218, 7, 114, 226, 82, 62, 93, 224, 62].map(&:chr).each do |c|
      assert_equal c, @encrypter.encrypt('a')
    end
    assert_equal 56.chr, @encrypter.encrypt('a')
    @encrypter.reset!
    Random.stub(:rand, 1) { @encrypter.header(@mtime) }
    [100, 218, 7, 114, 226, 82, 62, 93, 224, 62].map(&:chr).each do |c|
      assert_equal c, @encrypter.encrypt('a')
    end
  end
end

class TraditionalDecrypterTest < MiniTest::Test
  def setup
    @decrypter = ::Zip::TraditionalDecrypter.new('password')
  end

  def test_header_bytesize
    assert_equal 12, @decrypter.header_bytesize
  end

  def test_gp_flags
    assert_equal 9, @decrypter.gp_flags
  end

  def test_decrypt
    @decrypter.reset!([239, 57, 234, 154, 246, 80, 83, 221, 74, 200, 121, 91].pack('C*'))
    [100, 218, 7, 114, 226, 82, 62, 93, 224, 62].map(&:chr).each do |c|
      assert_equal 'a', @decrypter.decrypt(c)
    end
  end

  def test_reset!
    @decrypter.reset!([239, 57, 234, 154, 246, 80, 83, 221, 74, 200, 121, 91].pack('C*'))
    [100, 218, 7, 114, 226, 82, 62, 93, 224, 62].map(&:chr).each do |c|
      assert_equal 'a', @decrypter.decrypt(c)
    end
    assert_equal 91.chr, @decrypter.decrypt(2.chr)
    @decrypter.reset!([239, 57, 234, 154, 246, 80, 83, 221, 74, 200, 121, 91].pack('C*'))
    [100, 218, 7, 114, 226, 82, 62, 93, 224, 62].map(&:chr).each do |c|
      assert_equal 'a', @decrypter.decrypt(c)
    end
  end
end
