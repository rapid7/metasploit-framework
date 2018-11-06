require 'test_helper'

class NullEncrypterTest < MiniTest::Test
  def setup
    @encrypter = ::Zip::NullEncrypter.new
  end

  def test_header_bytesize
    assert_equal 0, @encrypter.header_bytesize
  end

  def test_gp_flags
    assert_equal 0, @encrypter.gp_flags
  end

  def test_header
    assert_empty @encrypter.header(nil)
  end

  def test_encrypt
    assert_nil @encrypter.encrypt(nil)

    ['', 'a' * 10, 0xffffffff].each do |data|
      assert_equal data, @encrypter.encrypt(data)
    end
  end

  def test_reset!
    assert_respond_to @encrypter, :reset!
  end
end

class NullDecrypterTest < MiniTest::Test
  def setup
    @decrypter = ::Zip::NullDecrypter.new
  end

  def test_header_bytesize
    assert_equal 0, @decrypter.header_bytesize
  end

  def test_gp_flags
    assert_equal 0, @decrypter.gp_flags
  end

  def test_decrypt
    assert_nil @decrypter.decrypt(nil)

    ['', 'a' * 10, 0xffffffff].each do |data|
      assert_equal data, @decrypter.decrypt(data)
    end
  end

  def test_reset!
    assert_respond_to @decrypter, :reset!
  end
end
