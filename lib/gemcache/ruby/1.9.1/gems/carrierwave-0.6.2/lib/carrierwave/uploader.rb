# encoding: utf-8

module CarrierWave

  ##
  # See CarrierWave::Uploader::Base
  #
  module Uploader

    ##
    # An uploader is a class that allows you to easily handle the caching and storage of
    # uploaded files. Please refer to the README for configuration options.
    #
    # Once you have an uploader you can use it in isolation:
    #
    #     my_uploader = MyUploader.new
    #     my_uploader.cache!(File.open(path_to_file))
    #     my_uploader.retrieve_from_store!('monkey.png')
    #
    # Alternatively, you can mount it on an ORM or other persistence layer, with
    # +CarrierWave::Mount#mount_uploader+. There are extensions for activerecord and datamapper
    # these are *very* simple (they are only a dozen lines of code), so adding your own should
    # be trivial.
    #
    class Base
      attr_reader :file

      include CarrierWave::Uploader::Callbacks
      include CarrierWave::Uploader::Proxy
      include CarrierWave::Uploader::Url
      include CarrierWave::Uploader::Mountable
      include CarrierWave::Uploader::Cache
      include CarrierWave::Uploader::Store
      include CarrierWave::Uploader::Download
      include CarrierWave::Uploader::Remove
      include CarrierWave::Uploader::ExtensionWhitelist
      include CarrierWave::Uploader::Processing
      include CarrierWave::Uploader::Versions
      include CarrierWave::Uploader::DefaultUrl
      include CarrierWave::Uploader::Configuration
      include CarrierWave::Uploader::Serialization
    end # Base

  end # Uploader
end # CarrierWave
