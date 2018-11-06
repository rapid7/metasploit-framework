# frozen_string_literal: true
require 'fileutils'

module YARD
  # The data store for the {Registry}.
  #
  # @see Registry
  # @see Serializers::YardocSerializer
  class RegistryStore
    # @deprecated The registry no longer tracks proxy types
    attr_reader :proxy_types
    attr_reader :file, :checksums

    def initialize
      @file = nil
      @checksums = {}
      @store = {}
      @proxy_types = {}
      @object_types = {:root => [:root]}
      @notfound = {}
      @loaded_objects = 0
      @available_objects = 0
      @locales = {}
      @store[:root] = CodeObjects::RootObject.allocate
      @store[:root].send(:initialize, nil, :root)
    end

    # Gets a {CodeObjects::Base} from the store
    #
    # @param [String, Symbol] key the path name of the object to look for.
    #   If it is empty or :root, returns the {#root} object.
    # @return [CodeObjects::Base, nil] a code object or nil if none is found
    def get(key)
      key = :root if key == ''
      key = key.to_sym
      return @store[key] if @store[key]
      return if @loaded_objects >= @available_objects

      # check disk
      return if @notfound[key]
      obj = @serializer.deserialize(key)
      if obj
        @loaded_objects += 1
        put(key, obj)
      else
        @notfound[key] = true
        nil
      end
    end

    # Associates an object with a path
    # @param [String, Symbol] key the path name (:root or '' for root object)
    # @param [CodeObjects::Base] value the object to store
    # @return [CodeObjects::Base] returns +value+
    def put(key, value)
      if key == ''
        @object_types[:root] = [:root]
        @store[:root] = value
      else
        @notfound.delete(key.to_sym)
        (@object_types[value.type] ||= []) << key.to_s
        if @store[key.to_sym]
          @object_types[@store[key.to_sym].type].delete(key.to_s)
        end
        @store[key.to_sym] = value
      end
    end

    alias [] get
    alias []= put

    # Deletes an object at a given path
    # @param [#to_sym] key the key to delete
    # @return [void]
    def delete(key) @store.delete(key.to_sym) end

    # Gets all path names from the store. Loads the entire database
    # if +reload+ is +true+
    #
    # @param [Boolean] reload if false, does not load the entire database
    #   before a lookup.
    # @return [Array<Symbol>] the path names of all the code objects
    def keys(reload = false) load_all if reload; @store.keys end

    # Gets all code objects from the store. Loads the entire database
    # if +reload+ is +true+
    #
    # @param [Boolean] reload if false, does not load the entire database
    #   before a lookup.
    # @return [Array<CodeObjects::Base>] all the code objects
    def values(reload = false) load_all if reload; @store.values end

    # @param [Symbol] type the type to look for
    # @return [Array<String>] a list of object paths with a given
    #   {CodeObjects::Base#type}
    # @since 0.8.0
    def paths_for_type(type, reload = false)
      load_all if reload
      @object_types[type] || []
    end

    # @param [Symbol] type the type to look for
    # @return [Array<CodeObjects::Base>] a list of objects with a given
    #   {CodeObjects::Base#type}
    # @since 0.8.0
    def values_for_type(type, reload = false)
      load_all if reload
      paths_for_type(type).map {|t| @store[t.to_sym] }
    end

    # @return [CodeObjects::RootObject] the root object
    def root; @store[:root] end

    # @param [String] name the locale name.
    # @return [I18n::Locale] the locale object for +name+.
    # @since 0.8.3
    def locale(name)
      @locales[name] ||= load_locale(name)
    end

    # @param [String, nil] file the name of the yardoc db to load
    # @return [Boolean] whether the database was loaded
    def load(file = nil)
      initialize
      @file = file
      @serializer = Serializers::YardocSerializer.new(@file)
      load_yardoc
    end

    # Loads the .yardoc file and loads all cached objects into memory
    # automatically.
    #
    # @param [String, nil] file the name of the yardoc db to load
    # @return [Boolean] whether the database was loaded
    # @see #load_all
    # @since 0.5.1
    def load!(file = nil)
      if load(file)
        load_all
        true
      else
        false
      end
    end

    # Loads all cached objects into memory
    # @return [void]
    def load_all
      return unless @file
      return if @loaded_objects >= @available_objects
      log.debug "Loading entire database: #{@file} ..."
      objects = []

      all_disk_objects.sort_by(&:size).each do |path|
        obj = @serializer.deserialize(path, true)
        objects << obj if obj
      end

      objects.each do |obj|
        put(obj.path, obj)
      end

      @loaded_objects += objects.size
      log.debug "Loaded database (file='#{@file}' count=#{objects.size} total=#{@available_objects})"
    end

    # Saves the database to disk
    # @param [Boolean] merge if true, merges the data in memory with the
    #   data on disk, otherwise the data on disk is deleted.
    # @param [String, nil] file if supplied, the name of the file to save to
    # @return [Boolean] whether the database was saved
    def save(merge = true, file = nil)
      if file && file != @file
        @file = file
        @serializer = Serializers::YardocSerializer.new(@file)
      end
      destroy unless merge

      sdb = Registry.single_object_db
      if sdb == true || sdb.nil?
        @serializer.serialize(@store)
      else
        values(false).each do |object|
          @serializer.serialize(object)
        end
      end
      write_proxy_types
      write_object_types
      write_checksums
      write_complete_lock
      true
    end

    # (see Serializers::YardocSerializer#lock_for_writing)
    # @param file [String] if supplied, the path to the database
    def lock_for_writing(file = nil, &block)
      Serializers::YardocSerializer.new(file || @file).lock_for_writing(&block)
    end

    # (see Serializers::YardocSerializer#locked_for_writing?)
    # @param file [String] if supplied, the path to the database
    def locked_for_writing?(file = nil)
      Serializers::YardocSerializer.new(file || @file).locked_for_writing?
    end

    # Deletes the .yardoc database on disk
    #
    # @param [Boolean] force if force is not set to true, the file/directory
    #   will only be removed if it ends with .yardoc. This helps with
    #   cases where the directory might have been named incorrectly.
    # @return [Boolean] true if the .yardoc database was deleted, false
    #   otherwise.
    def destroy(force = false)
      if (!force && file =~ /\.yardoc$/) || force
        if File.file?(@file)
          # Handle silent upgrade of old .yardoc format
          File.unlink(@file)
        elsif File.directory?(@file)
          FileUtils.rm_rf(@file)
        end
        true
      else
        false
      end
    end

    protected

    def objects_path
      @serializer.objects_path
    end

    # @deprecated The registry no longer tracks proxy types
    def proxy_types_path
      @serializer.proxy_types_path
    end

    def checksums_path
      @serializer.checksums_path
    end

    def object_types_path
      @serializer.object_types_path
    end

    def load_yardoc
      return false unless @file
      if File.directory?(@file) # new format
        @loaded_objects = 0
        @available_objects = all_disk_objects.size
        load_proxy_types
        load_checksums
        load_root
        load_object_types
        true
      elsif File.file?(@file) # old format
        load_yardoc_old
        true
      else
        false
      end
    end

    private

    def load_yardoc_old
      @store, @proxy_types = *Marshal.load(File.read_binary(@file))
    end

    # @deprecated The registry no longer tracks proxy types
    def load_proxy_types
      return unless File.file?(proxy_types_path)
      @proxy_types = Marshal.load(File.read_binary(proxy_types_path))
    end

    def load_object_types
      if File.file?(object_types_path)
        @object_types = Marshal.load(File.read_binary(object_types_path))
      else # migrate db without object_types
        values.each do |object|
          (@object_types[object.type] ||= []) << object.path
        end
      end
    end

    def load_checksums
      return unless File.file?(checksums_path)
      lines = File.readlines(checksums_path).map do |line|
        line.strip.split(/\s+/)
      end
      @checksums = Hash[lines]
    end

    def load_root
      root = @serializer.deserialize('root')
      return if root.nil?

      @loaded_objects += 1
      if root.is_a?(Hash) # single object db
        log.debug "Loading single object DB from .yardoc"
        @loaded_objects += (root.keys.size - 1)
        @store = root
      else # just the root object
        @store[:root] = root
      end
    end

    def load_locale(name)
      locale = I18n::Locale.new(name)
      locale.load(Registry.po_dir)
      locale
    end

    def all_disk_objects
      Dir.glob(File.join(objects_path, '**/*')).select {|f| File.file?(f) }
    end

    # @deprecated The registry no longer tracks proxy types
    def write_proxy_types
      File.open!(proxy_types_path, 'wb') {|f| f.write(Marshal.dump(@proxy_types)) }
    end

    def write_object_types
      File.open!(object_types_path, 'wb') {|f| f.write(Marshal.dump(@object_types)) }
    end

    def write_checksums
      File.open!(checksums_path, 'w') do |f|
        @checksums.each {|k, v| f.puts("#{k} #{v}") }
      end
    end

    def write_complete_lock
      File.open!(@serializer.complete_lock_path, 'w') {}
    end
  end
end
