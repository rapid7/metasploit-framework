# encoding: utf-8

require 'test_helper'

class ErrorsTest < MiniTest::Test
  def test_rescue_legacy_zip_error
    raise ::Zip::Error
  rescue ::Zip::ZipError
  end

  def test_rescue_legacy_zip_entry_exists_error
    raise ::Zip::EntryExistsError
  rescue ::Zip::ZipEntryExistsError
  end

  def test_rescue_legacy_zip_destination_file_exists_error
    raise ::Zip::DestinationFileExistsError
  rescue ::Zip::ZipDestinationFileExistsError
  end

  def test_rescue_legacy_zip_compression_method_error
    raise ::Zip::CompressionMethodError
  rescue ::Zip::ZipCompressionMethodError
  end

  def test_rescue_legacy_zip_entry_name_error
    raise ::Zip::EntryNameError
  rescue ::Zip::ZipEntryNameError
  end

  def test_rescue_legacy_zip_internal_error
    raise ::Zip::InternalError
  rescue ::Zip::ZipInternalError
  end
end
