# encoding: utf-8

require 'test_helper'

class ZipUnicodeFileNamesAndComments < MiniTest::Test
  FILENAME = File.join(File.dirname(__FILE__), 'test1.zip')

  def test_unicode_file_name
    file_entrys = ['текстовыйфайл.txt', 'Résumé.txt', '슬레이어스휘.txt']
    directory_entrys = ['папка/текстовыйфайл.txt', 'Résumé/Résumé.txt', '슬레이어스휘/슬레이어스휘.txt']
    stream = ::Zip::OutputStream.open(FILENAME) do |io|
      file_entrys.each do |filename|
        io.put_next_entry(filename)
        io.write(filename)
      end
      directory_entrys.each do |filepath|
        io.put_next_entry(filepath)
        io.write(filepath)
      end
    end
    assert(!stream.nil?)
    ::Zip::InputStream.open(FILENAME) do |io|
      file_entrys.each do |filename|
        entry = io.get_next_entry
        entry_name = entry.name
        entry_name = entry_name.force_encoding('UTF-8')
        assert(filename == entry_name)
      end
      directory_entrys.each do |filepath|
        entry = io.get_next_entry
        entry_name = entry.name
        entry_name = entry_name.force_encoding('UTF-8')
        assert(filepath == entry_name)
      end
    end

    ::Zip.force_entry_names_encoding = 'UTF-8'
    ::Zip::File.open(FILENAME) do |zip|
      file_entrys.each do |filename|
        refute_nil(zip.find_entry(filename))
      end
      directory_entrys.each do |filepath|
        refute_nil(zip.find_entry(filepath))
      end
    end
    ::Zip.force_entry_names_encoding = nil

    ::File.unlink(FILENAME)
  end

  def test_unicode_comment
    str = '渠道升级'
    ::Zip::File.open(FILENAME, Zip::File::CREATE) do |z|
      z.comment = str
    end

    ::Zip::File.open(FILENAME) do |z|
      assert(z.comment.force_encoding('UTF-8') == str)
    end
    ::File.unlink(FILENAME)
  end
end
