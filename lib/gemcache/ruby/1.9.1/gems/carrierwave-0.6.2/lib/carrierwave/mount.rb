# encoding: utf-8

module CarrierWave

  ##
  # If a Class is extended with this module, it gains the mount_uploader
  # method, which is used for mapping attributes to uploaders and allowing
  # easy assignment.
  #
  # You can use mount_uploader with pretty much any class, however it is
  # intended to be used with some kind of persistent storage, like an ORM.
  # If you want to persist the uploaded files in a particular Class, it
  # needs to implement a `read_uploader` and a `write_uploader` method.
  #
  module Mount

    ##
    # === Returns
    #
    # [Hash{Symbol => CarrierWave}] what uploaders are mounted on which columns
    #
    def uploaders
      @uploaders ||= {}
      @uploaders = superclass.uploaders.merge(@uploaders) if superclass.respond_to?(:uploaders)
      @uploaders
    end

    def uploader_options
      @uploader_options ||= {}
      @uploader_options = superclass.uploader_options.merge(@uploader_options) if superclass.respond_to?(:uploader_options)
      @uploader_options
    end

    ##
    # Return a particular option for a particular uploader
    #
    # === Parameters
    #
    # [column (Symbol)] The column the uploader is mounted at
    # [option (Symbol)] The option, e.g. validate_integrity
    #
    # === Returns
    #
    # [Object] The option value
    #
    def uploader_option(column, option)
      if uploader_options[column].has_key?(option)
        uploader_options[column][option]
      else
        uploaders[column].send(option)
      end
    end

    ##
    # Mounts the given uploader on the given column. This means that assigning
    # and reading from the column will upload and retrieve files. Supposing
    # that a User class has an uploader mounted on image, you can assign and
    # retrieve files like this:
    #
    #     @user.image # => <Uploader>
    #     @user.image.store!(some_file_object)
    #
    #     @user.image.url # => '/some_url.png'
    #
    # It is also possible (but not recommended) to ommit the uploader, which
    # will create an anonymous uploader class.
    #
    # Passing a block makes it possible to customize the uploader. This can be
    # convenient for brevity, but if there is any significatnt logic in the
    # uploader, you should do the right thing and have it in its own file.
    #
    # === Added instance methods
    #
    # Supposing a class has used +mount_uploader+ to mount an uploader on a column
    # named +image+, in that case the following methods will be added to the class:
    #
    # [image]                   Returns an instance of the uploader only if anything has been uploaded
    # [image=]                  Caches the given file
    #
    # [image_url]               Returns the url to the uploaded file
    #
    # [image_cache]             Returns a string that identifies the cache location of the file
    # [image_cache=]            Retrieves the file from the cache based on the given cache name
    #
    # [remote_image_url]        Returns previously cached remote url
    # [remote_image_url=]       Retrieve the file from the remote url
    #
    # [remove_image]            An attribute reader that can be used with a checkbox to mark a file for removal
    # [remove_image=]           An attribute writer that can be used with a checkbox to mark a file for removal
    # [remove_image?]           Whether the file should be removed when store_image! is called.
    #
    # [store_image!]            Stores a file that has been assigned with +image=+
    # [remove_image!]           Removes the uploaded file from the filesystem.
    #
    # [image_integrity_error]   Returns an error object if the last file to be assigned caused an integrity error
    # [image_processing_error]  Returns an error object if the last file to be assigned caused a processing error
    #
    # [write_image_identifier]  Uses the write_uploader method to set the identifier.
    # [image_identifier]        Reads out the identifier of the file
    #
    # === Parameters
    #
    # [column (Symbol)]                   the attribute to mount this uploader on
    # [uploader (CarrierWave::Uploader)]  the uploader class to mount
    # [options (Hash{Symbol => Object})]  a set of options
    # [&block (Proc)]                     customize anonymous uploaders
    #
    # === Options
    #
    # [:mount_on => Symbol] if the name of the column to be serialized to differs you can override it using this option
    # [:ignore_integrity_errors => Boolean] if set to true, integrity errors will result in caching failing silently
    # [:ignore_processing_errors => Boolean] if set to true, processing errors will result in caching failing silently
    #
    # === Examples
    #
    # Mounting uploaders on different columns.
    #
    #     class Song
    #       mount_uploader :lyrics, LyricsUploader
    #       mount_uploader :alternative_lyrics, LyricsUploader
    #       mount_uploader :file, SongUploader
    #     end
    #
    # This will add an anonymous uploader with only the default settings:
    #
    #     class Data
    #       mount_uploader :csv
    #     end
    #
    # this will add an anonymous uploader overriding the store_dir:
    #
    #     class Product
    #       mount_uploader :blueprint do
    #         def store_dir
    #           'blueprints'
    #         end
    #       end
    #     end
    #
    def mount_uploader(column, uploader=nil, options={}, &block)
      if block_given?
        uploader = Class.new(uploader || CarrierWave::Uploader::Base)
        uploader.class_eval(&block)
        uploader.recursively_apply_block_to_versions(&block)
      else
        uploader ||= Class.new(CarrierWave::Uploader::Base)
      end

      uploaders[column.to_sym] = uploader
      uploader_options[column.to_sym] = options

      include CarrierWave::Mount::Extension

      # Make sure to write over accessors directly defined on the class.
      # Simply super to the included module below.
      class_eval <<-RUBY, __FILE__, __LINE__+1
        def #{column}; super; end
        def #{column}=(new_file); super; end
      RUBY

      # Mixing this in as a Module instead of class_evaling directly, so we
      # can maintain the ability to super to any of these methods from within
      # the class.
      mod = Module.new
      include mod
      mod.class_eval <<-RUBY, __FILE__, __LINE__+1

        def #{column}
          _mounter(:#{column}).uploader
        end

        def #{column}=(new_file)
          _mounter(:#{column}).cache(new_file)
        end

        def #{column}?
          !_mounter(:#{column}).blank?
        end

        def #{column}_url(*args)
          _mounter(:#{column}).url(*args)
        end

        def #{column}_cache
          _mounter(:#{column}).cache_name
        end

        def #{column}_cache=(cache_name)
          _mounter(:#{column}).cache_name = cache_name
        end

        def remote_#{column}_url
          _mounter(:#{column}).remote_url
        end

        def remote_#{column}_url=(url)
          _mounter(:#{column}).remote_url = url
        end

        def remove_#{column}
          _mounter(:#{column}).remove
        end

        def remove_#{column}!
          _mounter(:#{column}).remove!
        end

        def remove_#{column}=(value)
          _mounter(:#{column}).remove = value
        end

        def remove_#{column}?
          _mounter(:#{column}).remove?
        end

        def store_#{column}!
          _mounter(:#{column}).store!
        end

        def #{column}_integrity_error
          _mounter(:#{column}).integrity_error
        end

        def #{column}_processing_error
          _mounter(:#{column}).processing_error
        end

        def write_#{column}_identifier
          _mounter(:#{column}).write_identifier
        end

        def #{column}_identifier
          _mounter(:#{column}).identifier
        end

        def store_previous_model_for_#{column}
          serialization_column = _mounter(:#{column}).serialization_column

          if #{column}.remove_previously_stored_files_after_update && send(:"\#{serialization_column}_changed?")
            @previous_model_for_#{column} ||= self.find_previous_model_for_#{column}
          end
        end

        def find_previous_model_for_#{column}
          self.class.find(to_key.first)
        end

        def remove_previously_stored_#{column}
          if @previous_model_for_#{column} && @previous_model_for_#{column}.#{column}.path != #{column}.path
            @previous_model_for_#{column}.#{column}.remove!
            @previous_model_for_#{column} = nil
          end
        end

      RUBY
    end

    module Extension

      ##
      # overwrite this to read from a serialized attribute
      #
      def read_uploader(column); end

      ##
      # overwrite this to write to a serialized attribute
      #
      def write_uploader(column, identifier); end

    private

      def _mounter(column)
        # We cannot memoize in frozen objects :(
        return Mounter.new(self, column) if frozen?
        @_mounters ||= {}
        @_mounters[column] ||= Mounter.new(self, column)
      end

    end # Extension

    # this is an internal class, used by CarrierWave::Mount so that
    # we don't pollute the model with a lot of methods.
    class Mounter #:nodoc:
      attr_reader :column, :record, :remote_url, :integrity_error, :processing_error
      attr_accessor :remove

      def initialize(record, column, options={})
        @record = record
        @column = column
        @options = record.class.uploader_options[column]
      end

      def write_identifier
        if remove?
          record.write_uploader(serialization_column, '')
        elsif not uploader.identifier.blank?
          record.write_uploader(serialization_column, uploader.identifier)
        end
      end

      def identifier
        record.read_uploader(serialization_column)
      end

      def uploader
        @uploader ||= record.class.uploaders[column].new(record, column)

        if @uploader.blank? and not identifier.blank?
          @uploader.retrieve_from_store!(identifier)
        end
        return @uploader
      end

      def cache(new_file)
        uploader.cache!(new_file)
        @integrity_error = nil
        @processing_error = nil
      rescue CarrierWave::IntegrityError => e
        @integrity_error = e
        raise e unless option(:ignore_integrity_errors)
      rescue CarrierWave::ProcessingError => e
        @processing_error = e
        raise e unless option(:ignore_processing_errors)
      end

      def cache_name
        uploader.cache_name
      end

      def cache_name=(cache_name)
        uploader.retrieve_from_cache!(cache_name) unless uploader.cached?
      rescue CarrierWave::InvalidParameter
      end

      def remote_url=(url)
        @remote_url = url
        uploader.download!(url)
      end

      def store!
        unless uploader.blank?
          if remove?
            uploader.remove!
          else
            uploader.store!
          end
        end
      end

      def url(*args)
        uploader.url(*args)
      end

      def blank?
        uploader.blank?
      end

      def remove?
        !remove.blank? and remove !~ /\A0|false$\z/
      end

      def remove!
        uploader.remove!
      end

      def serialization_column
        option(:mount_on) || column
      end

      attr_accessor :uploader_options

    private

      def option(name)
        self.uploader_options ||= {}
        self.uploader_options[name] ||= record.class.uploader_option(column, name)
      end

    end # Mounter

  end # Mount
end # CarrierWave
