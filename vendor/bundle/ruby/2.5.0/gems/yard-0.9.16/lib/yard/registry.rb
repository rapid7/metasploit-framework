# frozen_string_literal: true
require 'fileutils'
require 'digest/sha1'

module YARD
  # The +Registry+ is the centralized data store for all {CodeObjects} created
  # during parsing. The storage is a key value store with the object's path
  # (see {CodeObjects::Base#path}) as the key and the object itself as the value.
  # Object paths must be unique to be stored in the Registry. All lookups for
  # objects are done on the singleton Registry instance using the {Registry.at}
  # or {Registry.resolve} methods.
  #
  # == Saving / Loading a Registry
  # The registry is saved to a "yardoc file" (actually a directory), which can
  # be loaded back to perform any lookups. See {Registry.load!} and
  # {Registry.save} for information on saving and loading of a yardoc file.
  #
  # == Threading Notes
  # The registry class is a singleton class that is accessed directly in many
  # places across YARD. To mitigate threading issues, YARD (0.6.5+) makes
  # the Registry thread local. This means all access to a registry for a specific
  # object set must occur in the originating thread.
  #
  # @example Loading the Registry
  #   Registry.load!('/path/to/yardocfile') # loads all objects into memory
  #   Registry.at('YARD::CodeObjects::Base').docstring
  #   # => "+Base+ is the superclass of all code objects ..."
  # @example Getting an object by a specific path
  #   Registry.at('YARD::CodeObjects::Base#docstring')
  # @example Performing a lookup on a method anywhere in the inheritance tree
  #   Registry.resolve(P('YARD::CodeObjects::Base'), '#docstring', true)
  module Registry
    DEFAULT_YARDOC_FILE = ".yardoc"
    LOCAL_YARDOC_INDEX = File.expand_path(File.join(Config::CONFIG_DIR, 'gem_index'))
    DEFAULT_PO_DIR = "po"

    extend Enumerable

    class << self
      # @group Getting .yardoc File Locations

      # Returns the .yardoc file associated with a gem.
      #
      # @param [String] gem the name of the gem to search for
      # @param [String] ver_require an optional Gem version requirement
      # @param [Boolean] for_writing whether or not the method should search
      #   for writable locations
      # @return [String] if +for_writing+ is set to +true+, returns the best
      #   location suitable to write the .yardoc file. Otherwise, the first
      #   existing location associated with the gem's .yardoc file.
      # @return [nil] if +for_writing+ is set to false and no yardoc file
      #   is found, returns nil.
      def yardoc_file_for_gem(gem, ver_require = ">= 0", for_writing = false)
        specs = YARD::GemIndex.find_all_by_name(gem, ver_require)
        return if specs.empty?

        result = nil
        specs.reverse.each do |spec|
          if gem =~ /^yard-doc-/
            path = File.join(spec.full_gem_path, DEFAULT_YARDOC_FILE)
            result = File.exist?(path) && !for_writing ? path : nil
            result ? break : next
          end

          if for_writing
            result = global_yardoc_file(spec, for_writing) ||
                     old_global_yardoc_file(spec, for_writing) ||
                     local_yardoc_file(spec, for_writing)
          else
            result = local_yardoc_file(spec, for_writing) ||
                     global_yardoc_file(spec, for_writing) ||
                     old_global_yardoc_file(spec, for_writing)
          end

          break if result
        end

        result
      end

      # Gets/sets the yardoc filename
      # @return [String] the yardoc filename
      # @see DEFAULT_YARDOC_FILE
      attr_accessor :yardoc_file
      undef yardoc_file, yardoc_file=
      def yardoc_file=(v) Thread.current[:__yard_yardoc_file__] = v end

      def yardoc_file
        Thread.current[:__yard_yardoc_file__] ||= DEFAULT_YARDOC_FILE
      end

      # @group Loading Data from Disk

      # Loads the registry and/or parses a list of files
      #
      # @example Loads the yardoc file or parses files 'a', 'b' and 'c' (but not both)
      #   Registry.load(['a', 'b', 'c'])
      # @example Reparses files 'a' and 'b' regardless of whether yardoc file exists
      #   Registry.load(['a', 'b'], true)
      # @param [String, Array] files if +files+ is an Array, it should represent
      #   a list of files that YARD should parse into the registry. If reload is
      #   set to false and the yardoc file already exists, these files are skipped.
      #   If files is a String, it should represent the yardoc file to load
      #   into the registry.
      # @param [Boolean] reparse if reparse is false and a yardoc file already
      #   exists, any files passed in will be ignored.
      # @return [Registry] the registry object (for chaining)
      # @raise [ArgumentError] if files is not a String or Array
      def load(files = [], reparse = false)
        if files.is_a?(Array)
          if File.exist?(yardoc_file) && !reparse
            load_yardoc
          else
            size = thread_local_store.keys.size
            YARD.parse(files)
            save if thread_local_store.keys.size > size
          end
        elsif files.is_a?(String)
          load_yardoc(files)
        else
          raise ArgumentError, "Must take a list of files to parse or the .yardoc file to load."
        end
        self
      end

      # Loads a yardoc file directly
      #
      # @param [String] file the yardoc file to load.
      # @return [Registry] the registry object (for chaining)
      def load_yardoc(file = yardoc_file)
        clear
        thread_local_store.load(file)
        self
      end

      # Loads a yardoc file and forces all objects cached on disk into
      # memory. Equivalent to calling {load_yardoc} followed by {load_all}
      #
      # @param [String] file the yardoc file to load
      # @return [Registry] the registry object (for chaining)
      # @see #load_yardoc
      # @see #load_all
      # @since 0.5.1
      def load!(file = yardoc_file)
        clear
        thread_local_store.load!(file)
        self
      end

      # Forces all objects cached on disk into memory
      #
      # @example Loads all objects from disk
      #   Registry.load
      #   Registry.all.count #=> 0
      #   Registry.load_all
      #   Registry.all.count #=> 17
      # @return [Registry] the registry object (for chaining)
      # @since 0.5.1
      def load_all
        thread_local_store.load_all
        self
      end

      # @group Saving and Deleting Data from Disk

      # Saves the registry to +file+
      #
      # @param [String] file the yardoc file to save to
      # @return [Boolean] true if the file was saved
      def save(merge = false, file = yardoc_file)
        thread_local_store.save(merge, file)
      end

      # Deletes the yardoc file from disk
      # @return [void]
      def delete_from_disk
        thread_local_store.destroy
      end

      # @group Adding and Deleting Objects from the Registry

      # Registers a new object with the registry
      #
      # @param [CodeObjects::Base] object the object to register
      # @return [CodeObjects::Base] the registered object
      def register(object)
        return if object.is_a?(CodeObjects::Proxy)
        thread_local_store[object.path] = object
      end

      # Deletes an object from the registry
      # @param [CodeObjects::Base] object the object to remove
      # @return [void]
      def delete(object)
        thread_local_store.delete(object.path)
      end

      # Clears the registry
      # @return [void]
      def clear
        self.thread_local_store = RegistryStore.new
      end

      # Creates a pessmistic transactional lock on the database for writing.
      # Use with {YARD.parse} to ensure the database is not written multiple
      # times.
      #
      # @see locked_for_writing?
      def lock_for_writing(file = yardoc_file, &block)
        thread_local_store.lock_for_writing(file, &block)
      end

      # (see Serializers::YardocSerializer#locked_for_writing?)
      def locked_for_writing?(file = yardoc_file)
        thread_local_store.locked_for_writing?(file)
      end

      # @group Accessing Objects in the Registry

      # Iterates over {all} with no arguments
      def each(&block)
        all.each(&block)
      end

      # Returns all objects in the registry that match one of the types provided
      # in the +types+ list (if +types+ is provided).
      #
      # @example Returns all objects
      #   Registry.all
      # @example Returns all classes and modules
      #   Registry.all(:class, :module)
      # @param [Array<Symbol>] types an optional list of types to narrow the
      #   objects down by. Equivalent to performing a select:
      #     +Registry.all.select {|o| types.include(o.type) }+
      # @return [Array<CodeObjects::Base>] the list of objects found
      # @see CodeObjects::Base#type
      def all(*types)
        if types.empty?
          thread_local_store.values.select {|obj| obj != root }
        else
          list = []
          types.each do |type|
            list += thread_local_store.values_for_type(type)
          end
          list
        end
      end

      # Returns the paths of all of the objects in the registry.
      # @param [Boolean] reload whether to load entire database
      # @return [Array<String>] all of the paths in the registry.
      def paths(reload = false)
        thread_local_store.keys(reload).map(&:to_s)
      end

      # Returns the object at a specific path.
      # @param [String, :root] path the pathname to look for. If +path+ is +root+,
      #   returns the {root} object.
      # @return [CodeObjects::Base] the object at path
      # @return [nil] if no object is found
      def at(path) path ? thread_local_store[path] : nil end
      alias [] at

      # The root namespace object.
      # @return [CodeObjects::RootObject] the root object in the namespace
      def root; thread_local_store[:root] end

      # @param [String] name the locale name.
      # @return [I18n::Locale] the locale object for +name+.
      # @since 0.8.3
      def locale(name)
        thread_local_store.locale(name)
      end

      # Attempts to find an object by name starting at +namespace+, performing
      # a lookup similar to Ruby's method of resolving a constant in a namespace.
      #
      # @example Looks for instance method #reverse starting from A::B::C
      #   Registry.resolve(P("A::B::C"), "#reverse")
      # @example Looks for a constant in the root namespace
      #   Registry.resolve(nil, 'CONSTANT')
      # @example Looks for a class method respecting the inheritance tree
      #   Registry.resolve(myclass, 'mymethod', true)
      # @example Looks for a constant but returns a proxy if not found
      #   Registry.resolve(P('A::B::C'), 'D', false, true) # => #<yardoc proxy A::B::C::D>
      # @example Looks for a complex path from a namespace
      #   Registry.resolve(P('A::B'), 'B::D') # => #<yardoc class A::B::D>
      # @param [CodeObjects::NamespaceObject, nil] namespace the starting namespace
      #   (module or class). If +nil+ or +:root+, starts from the {root} object.
      # @param [String, Symbol] name the name (or complex path) to look for from
      #   +namespace+.
      # @param [Boolean] inheritance Follows inheritance chain (mixins, superclass)
      #   when performing name resolution if set to +true+.
      # @param [Boolean] proxy_fallback If +true+, returns a proxy representing
      #   the unresolved path (namespace + name) if no object is found.
      # @param [Symbol, nil] type the {CodeObjects::Base#type} that the resolved
      #   object must be equal to. No type checking if nil.
      # @return [CodeObjects::Base] the object if it is found
      # @return [CodeObjects::Proxy] a Proxy representing the object if
      #   +proxy_fallback+ is +true+.
      # @return [nil] if +proxy_fallback+ is +false+ and no object was found.
      # @see P
      def resolve(namespace, name, inheritance = false, proxy_fallback = false, type = nil)
        thread_local_resolver.lookup_by_path name,
          :namespace => namespace, :inheritance => inheritance,
          :proxy_fallback => proxy_fallback, :type => type
      end

      # @group Managing Source File Checksums

      # @return [Hash{String => String}] a set of checksums for files
      def checksums
        thread_local_store.checksums
      end

      # @param [String] data data to checksum
      # @return [String] the SHA1 checksum for data
      def checksum_for(data)
        Digest::SHA1.hexdigest(data)
      end

      # @group Managing Internal State (Advanced / Testing Only)

      # Whether or not the Registry storage should load everything into a
      # single object database (for disk efficiency), or spread them out
      # (for load time efficiency).
      #
      # @note Setting this attribute to nil will offload the decision to
      #   the {RegistryStore storage adapter}.
      # @return [Boolean, nil] if this value is set to nil, the storage
      #   adapter will decide how to store the data.
      attr_accessor :single_object_db
      undef single_object_db, single_object_db=
      def single_object_db=(v) Thread.current[:__yard_single_db__] = v end
      def single_object_db; Thread.current[:__yard_single_db__] end

      # The assumed types of a list of paths. This method is used by CodeObjects::Base
      # @return [{String => Symbol}] a set of unresolved paths and their assumed type
      # @private
      # @deprecated The registry no longer globally tracks proxy types.
      def proxy_types
        thread_local_store.proxy_types
      end

      # @group I18n features

      # Gets/sets the directory that has LANG.po files
      # @return [String] the directory that has .po files
      attr_accessor :po_dir
      undef po_dir, po_dir=
      def po_dir=(dir) Thread.current[:__yard_po_dir__] = dir end

      def po_dir
        Thread.current[:__yard_po_dir__] ||= DEFAULT_PO_DIR
      end

      # @group Legacy Methods

      # The registry singleton instance.
      #
      # @deprecated use Registry.methodname directly.
      # @return [Registry] returns the registry instance
      def instance; self end

      private

      # @group Accessing Objects in the Registry

      # Attempts to resolve a name in a namespace
      #
      # @param [CodeObjects::NamespaceObject] namespace the starting namespace
      # @param [String] name the name to look for
      # @param [Symbol, nil] type the {CodeObjects::Base#type} that the resolved
      #   object must be equal to
      def partial_resolve(namespace, name, type = nil)
        obj = at(name) || at('#' + name) if namespace.root?
        return obj if obj && (type.nil? || obj.type == type)
        [CodeObjects::NSEP, CodeObjects::CSEP, ''].each do |s|
          next if s.empty? && name =~ /^\w/
          path = name
          path = [namespace.path, name].join(s) if namespace != root
          found = at(path)
          return found if found && (type.nil? || found.type == type)
        end
        nil
      end

      # @group Retrieving yardoc File Locations

      def global_yardoc_file(spec, for_writing = false)
        path = spec.doc_dir
        yfile = spec.doc_dir(DEFAULT_YARDOC_FILE)
        if for_writing
          if File.writable?(path) ||
             (!File.directory?(path) && File.writable?(File.dirname(path)))
            return yfile
          end
        elsif !for_writing && File.exist?(yfile)
          return yfile
        end
      end

      def old_global_yardoc_file(spec, for_writing = false)
        path = spec.full_gem_path
        yfile = File.join(path, DEFAULT_YARDOC_FILE)
        return yfile if for_writing && File.writable?(path)
        return yfile if !for_writing && File.exist?(yfile)
      end

      def local_yardoc_file(spec, for_writing = false)
        path = Registry::LOCAL_YARDOC_INDEX
        FileUtils.mkdir_p(path) if for_writing
        path = File.join(path, "#{spec.full_name}.yardoc")
        if for_writing
          path
        else
          File.exist?(path) ? path : nil
        end
      end

      # @group Threading support

      # @since 0.6.5
      def thread_local_store
        Thread.current[:__yard_registry__] ||= clear
      end

      # @since 0.6.5
      def thread_local_store=(value)
        Thread.current[:__yard_registry__] = value
      end

      # @since 0.9.1
      def thread_local_resolver
        Thread.current[:__yard_resolver__] ||= RegistryResolver.new
      end
    end
  end
end
