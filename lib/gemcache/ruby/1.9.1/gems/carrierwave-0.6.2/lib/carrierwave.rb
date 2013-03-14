# encoding: utf-8

require 'fileutils'
require 'active_support/core_ext/object/blank'
require 'active_support/core_ext/class/attribute'

require 'active_support/concern'

module CarrierWave

  class << self
    attr_accessor :root, :base_path

    def configure(&block)
      CarrierWave::Uploader::Base.configure(&block)
    end

    def clean_cached_files!
      CarrierWave::Uploader::Base.clean_cached_files!
    end
  end

  class UploadError < StandardError; end
  class IntegrityError < UploadError; end
  class InvalidParameter < UploadError; end
  class ProcessingError < UploadError; end
  class DownloadError < UploadError; end

  autoload :SanitizedFile, 'carrierwave/sanitized_file'
  autoload :Mount, 'carrierwave/mount'
  autoload :RMagick, 'carrierwave/processing/rmagick'
  autoload :ImageScience, 'carrierwave/processing/image_science'
  autoload :MiniMagick, 'carrierwave/processing/mini_magick'
  autoload :MimeTypes, 'carrierwave/processing/mime_types'
  autoload :VERSION, 'carrierwave/version'

  module Storage
    autoload :Abstract, 'carrierwave/storage/abstract'
    autoload :File, 'carrierwave/storage/file'
    autoload :Fog, 'carrierwave/storage/fog'
  end

  module Uploader
    autoload :Base, 'carrierwave/uploader'
    autoload :Cache, 'carrierwave/uploader/cache'
    autoload :Store, 'carrierwave/uploader/store'
    autoload :Download, 'carrierwave/uploader/download'
    autoload :Callbacks, 'carrierwave/uploader/callbacks'
    autoload :Processing, 'carrierwave/uploader/processing'
    autoload :Versions, 'carrierwave/uploader/versions'
    autoload :Remove, 'carrierwave/uploader/remove'
    autoload :ExtensionWhitelist, 'carrierwave/uploader/extension_whitelist'
    autoload :DefaultUrl, 'carrierwave/uploader/default_url'
    autoload :Proxy, 'carrierwave/uploader/proxy'
    autoload :Url, 'carrierwave/uploader/url'
    autoload :Mountable, 'carrierwave/uploader/mountable'
    autoload :Configuration, 'carrierwave/uploader/configuration'
    autoload :Serialization, 'carrierwave/uploader/serialization'
  end

  module Compatibility
    autoload :Paperclip, 'carrierwave/compatibility/paperclip'
  end

  module Test
    autoload :Matchers, 'carrierwave/test/matchers'
  end

end

if defined?(Merb)

  CarrierWave.root = Merb.dir_for(:public)
  Merb::BootLoader.before_app_loads do
    # Setup path for uploaders and load all of them before classes are loaded
    Merb.push_path(:uploaders, Merb.root / 'app' / 'uploaders', '*.rb')
    Dir.glob(File.join(Merb.load_paths[:uploaders])).each {|f| require f }
  end

elsif defined?(Rails)

  module CarrierWave
    class Railtie < Rails::Railtie
      initializer "carrierwave.setup_paths" do
        CarrierWave.root = Rails.root.join(Rails.public_path).to_s
        CarrierWave.base_path = ENV['RAILS_RELATIVE_URL_ROOT']
      end

      initializer "carrierwave.active_record" do
        ActiveSupport.on_load :active_record do
          require 'carrierwave/orm/activerecord'
        end
      end
    end
  end

elsif defined?(Sinatra)
  if defined?(Padrino)
    CarrierWave.root = File.join(PADRINO_ROOT, "public")
  else

    CarrierWave.root = if Sinatra::Application.respond_to?(:public_folder)
      # Sinatra >= 1.3
      Sinatra::Application.public_folder
    else
      # Sinatra < 1.3
      Sinatra::Application.public
    end
  end

end
