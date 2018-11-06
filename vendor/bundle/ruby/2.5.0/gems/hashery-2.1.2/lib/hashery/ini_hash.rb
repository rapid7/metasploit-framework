module Hashery

  # Hash class with methods to read from and write into ini files.
  #
  # A ini file is a text file in a specific format,
  # it may include several fields which are sparated by
  # field headlines which are enclosured by "[]".
  # Each field may include several key-value pairs.
  #
  # Each key-value pair is represented by one line and
  # the value is sparated from the key by a "=".
  #
  # == Examples
  #
  # === Example ini file
  #
  #   # this is the first comment which will be saved in the comment attribute
  #   mail=info@example.com
  #   domain=example.com # this is a comment which will not be saved
  #   [database]
  #   db=example
  #   user=john
  #   passwd=very-secure
  #   host=localhost
  #   # this is another comment
  #   [filepaths]
  #   tmp=/tmp/example
  #   lib=/home/john/projects/example/lib
  #   htdocs=/home/john/projects/example/htdocs
  #   [ texts ]
  #   wellcome=Wellcome on my new website!
  #   Website description = This is only a example. # and another comment
  #
  # === Example object
  #
  # Ini#comment stores:
  #
  #   "this is the first comment which will be saved in the comment attribute"
  #
  # Ini's internal hash stores:
  #
  #   {
  #    "mail" => "info@example.com",
  #    "domain" => "example.com",
  #    "database" => {
  #     "db" => "example",
  #     "user" => "john",
  #     "passwd" => "very-secure",
  #     "host" => "localhost"
  #    },
  #    "filepaths" => {
  #     "tmp" => "/tmp/example",
  #     "lib" => "/home/john/projects/example/lib",
  #     "htdocs" => "/home/john/projects/example/htdocs"
  #    }
  #    "texts" => {
  #     "wellcome" => "Wellcome on my new website!",
  #     "Website description" => "This is only a example."
  #    }
  #   }
  #
  # As you can see this module gets rid of all comments, linebreaks
  # and unnecessary spaces at the beginning and the end of each
  # field headline, key or value.
  #
  # === Using the object
  #
  # Using the object is stright forward:
  #
  #   ini = IniHash.new("path/settings.ini")
  #   ini["mail"] = "info@example.com"
  #   ini["filepaths"] = { "tmp" => "/tmp/example" }
  #   ini.comment = "This is\na comment"
  #   puts ini["filepaths"]["tmp"]
  #   # => /tmp/example
  #   ini.write()
  # 
  # == Acknowlegements
  #
  # IniHash is based on ini.rb.
  #
  # Copyright (C) 2007 Jeena Paradies <info@jeenaparadies.net>

  class IniHash

    # TODO: Use class method for loading from file, not initializer.

    #
    # NOTE: In future versions, `#new` will not take a path, and `#load`
    # will have to be used.
    #
    def self.load(path, load=true)
      new(path, load)
    end

    #
    # The hash which holds all INI data.
    #
    attr_accessor :inihash

    #
    # The string which holds the comments on the top of the file
    #
    attr_accessor :comment

    #
    # Creating a new IniHash object.
    #
    # path - is a path to the ini file
    # load - if nil restores the data if possible
    #        if true restores the data, if not possible raises an error
    #        if false does not resotre the data
    #
    def initialize(path, load=nil)
      @path    = path if String === path
      @inihash = (Hash === path ? path.dup : {})

      if load or ( load.nil? and FileTest.readable_real? @path )
        restore()
      end
    end
    
    #
    # Retrive the ini data for the key +key+
    #
    def [](key)
      @inihash[key]
    end
    
    #
    # Set the ini data for the key +key+
    #
    # key   - Index key.
    # value - The value to index.
    #
    # Returns +value+.
    #
    def []=(key, value)
      #raise TypeError, "String expected" unless key.is_a? String
      key = key.to_str
     
      #raise TypeError, "String or Hash expected" unless value.is_a? String or value.is_a? Hash
      value = value.to_str unless Hash === value

      @inihash[key] = value
    end
    
    #
    # Restores the data from file into the object
    #
    def restore
      @inihash = IniHash.read_from_file(@path)
      @comment = IniHash.read_comment_from_file(@path)
    end

    #
    # Store data from the object in the file.
    #
    def save
      IniHash.write_to_file(@path, @inihash, @comment)
    end

    #
    # Deprecated: Save INI data to file path. Use #save instead.
    #
    def update
      warn 'IniHash#update is deprecated for this use, use IniHash#save instead.'
      save
    end

    #
    # Convert to hash by duplicating the underlying hash table.
    #
    def to_h
      @inihash.dup
    end

    alias :inspect :to_s

    #
    # Turn a hash (up to 2 levels deepness) into a ini string
    #
    # inihash - Hash representing the ini File. Default is a empty hash.
    #
    # Returns a string in the ini file format.
    #
    def to_s
      str = ""
      inihash.each do |key, value|
        if value.is_a? Hash
          str << "[#{key.to_s}]\n"
          value.each do |under_key, under_value|
            str << "#{under_key.to_s}=#{under_value.to_s unless under_value.nil?}\n"
          end
        else
          str << "#{key.to_s}=#{value.to_s unless value.nil?}\n"
        end
      end
      str
    end

    #
    # Delegate missing mthods to underlying Hash.
    #
    # TODO: Sublcass Hash instead of delegating.
    #
    def method_missing(s,*a,&b)
      @inihash.send(s, *a, &b) if @inihash.respond_to?(s)
    end

    #
    # Reading data from file
    #
    # path - a path to the ini file
    #
    # Returns a `Hash` which represents the data from the file.
    #
    def self.read_from_file(path)
      raise "file not found - #{path}" unless File.file?(path)

      inihash = {}
      headline = nil

      IO.foreach(path) do |line|
        line = line.strip.split(/#/)[0].to_s

        # read it only if the line doesn't begin with a "=" and is long enough
        unless line.length < 2 and line[0,1] == "="
          
          # it's a headline if the line begins with a "[" and ends with a "]"
          if line[0,1] == "[" and line[line.length - 1, line.length] == "]"

            # get rid of the [] and unnecessary spaces
            headline = line[1, line.length - 2 ].strip
            inihash[headline] = {}
          else
            key, value = line.split(/=/, 2)
            
            key = key.strip unless key.nil?
            value = value.strip unless value.nil?
            
            unless headline.nil?
              inihash[headline][key] = value
            else
              inihash[key] = value unless key.nil?
            end
          end        
        end
      end
      
      inihash
    end

    #
    # Reading comments from file
    #
    # path - a path to the INI file
    #
    # Returns a `String` with the comments from the beginning of the INI file.
    #
    def self.read_comment_from_file(path)
      comment = ""
      
      IO.foreach(path) do |line|
        line.strip!

        break unless line[0,1] == "#" or line == ""

        comment_line = line[1, line.length].to_s
        comment << "#{comment_line.strip}\n"
      end
      
      comment
    end

    #
    # Writing a ini hash into a file
    #
    # path    - Path to the INI file.
    # inihash - Hash representing the ini File. Default is a empty hash.
    # comment - String with comments which appear on the
    #           top of the file. Each line will get a "#" before.
    #           Default is no comment.
    #
    def self.write_to_file(path, inihash={}, comment=nil)
      raise TypeError, "String expected" unless comment.is_a? String or comment.nil?
      
      raise TypeError, "Hash expected" unless inihash.is_a? Hash
      File.open(path, "w") { |file|
        
        unless comment.nil?
          comment.each do |line|
            file << "# #{line}"
          end
        end

        file << IniHash.text(inihash)
      }
    end

    #
    # Turn a hash (up to 2 levels deepness) into a ini string
    #
    # inihash - Hash representing the ini File. Default is a empty hash.
    #
    # Returns a String in the ini file format.
    #
    # TODO: Rename `IniHash.text` method to something else ?
    #
    def self.text(inihash={})
      new(inihash).to_s
    end

    class << self
      # @deprecated
      alias_method :to_s, :text
    end

  end

end
