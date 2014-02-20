# -*- coding: binary -*-
require 'rexml/rexml'
require 'rexml/source'
require 'rexml/document'
require 'rexml/parsers/treeparser'
require 'rex/proto/http'
require 'uri'

module Rex
module Exploitation
module OpcodeDb

module OpcodeResult # :nodoc:
  def initialize(hash)
    @hash = hash
  end
  attr_reader :hash
end

###
#
# A cachable entry.
#
###
module Cachable

  def create(hash) # :nodoc:
    @Cache = {} unless (@Cache)
    if (hash_key(hash) and @Cache[hash_key(hash)])
      @Cache[hash_key(hash)]
    else
      @Cache[hash_key(hash)] = self.new(hash)
    end
  end

  def hash_key(hash) # :nodoc:
    hash['id'] || nil
  end

  def flush_cache # :nodoc:
    @Cache.clear
  end

end

###
#
# This class provides a general interface to items that come from that opcode
# database that have a symbolic entry identifier and name.
#
###
module DbEntry
  include OpcodeResult

  def initialize(hash)
    super

    @id   = hash['id'].to_i
    @name = hash['name']
  end

  #
  # Fields that could possibly be filtered on for this database entry.
  #
  def filter_hash
    {
      "id"   => id,
      "name" => name
    }
  end

  #
  # The unique server identifier.
  #
  attr_reader :id
  #
  # The unique name for this entry.
  #
  attr_reader :name
end

###
#
# This class represents a particular image module including its name,
# segments, imports, exports, base address, and so on.
#
###
class ImageModule
  include DbEntry

  ###
  #
  # This class contains information about a module-associated segment.
  #
  ###
  class Segment
    def initialize(hash)
      @type = hash['type']
      @base_address = hash['base_address'].to_i
      @size         = hash['segment_size'].to_i
      @writable     = hash['writable'] == "true" ? true : false
      @readable     = hash['readable'] == "true" ? true : false
      @executable   = hash['executable'] == "true" ? true : false
    end

    #
    # The type of the segment, such as ".text".
    #
    attr_reader :type
    #
    # The base address of the segment.
    #
    attr_reader :base_address
    #
    # The size of the segment in bytes.
    #
    attr_reader :size
    #
    # Boolean that indicates whether or not the segment is writable.
    #
    attr_reader :writable
    #
    # Boolean that indicates whether or not the segment is readable.
    #
    attr_reader :readable
    #
    # Boolean that indicates whether or not the segment is executable.
    #
    attr_reader :executable
  end

  ###
  #
  # This class contains information about a module-associated import.
  #
  ###
  class Import
    def initialize(hash)
      @name    = hash['name']
      @address = hash['address'].to_i
      @ordinal = hash['ordinal'].to_i
    end

    #
    # The name of the imported function.
    #
    attr_reader :name
    #
    # The address of the function pointer in the IAT.
    #
    attr_reader :address
    #
    # The ordinal of the imported symbol.
    #
    attr_reader :ordinal
  end

  ###
  #
  # This class contains information about a module-associated export.
  #
  ###
  class Export
    def initialize(hash)
      @name    = hash['name']
      @address = hash['address'].to_i
      @ordinal = hash['ordinal'].to_i
    end

    #
    # The name of the exported function.
    #
    attr_reader :name
    #
    # The address of the exported function.
    #
    attr_reader :address
    #
    # The ordinal of the exported symbol.
    #
    attr_reader :ordinal
  end

  class <<self
    include Cachable
    def hash_key(hash) # :nodoc:
      (hash['id'] || '') +
      (hash['segments'] || '').to_s +
      (hash['exports'] || '').to_s +
      (hash['imports'] || '').to_s
    end
  end

  def initialize(hash)
    super

    @locale       = Locale.create(hash['locale'])
    @maj_maj_ver  = hash['maj_maj_ver'].to_i
    @maj_min_ver  = hash['maj_min_ver'].to_i
    @min_maj_ver  = hash['min_maj_ver'].to_i
    @min_min_ver  = hash['min_min_ver'].to_i
    @timestamp    = Time.at(hash['timestamp'].to_i)
    @vendor       = hash['vendor']
    @base_address = hash['base_address'].to_i
    @image_size   = hash['image_size'].to_i

    @segments     = hash['segments'].map { |ent|
      Segment.new(ent)
    } if (hash['segments'])
    @imports     = hash['imports'].map { |ent|
      Import.new(ent)
    } if (hash['imports'])
    @exports     = hash['exports'].map { |ent|
      Export.new(ent)
    } if (hash['exports'])
    @platforms   = hash['platforms'].map { |ent|
      OsVersion.create(ent)
    } if (hash['platforms'])

    @segments  = [] unless(@segments)
    @imports   = [] unless(@imports)
    @exports   = [] unless(@exports)
    @platforms = [] unless(@platforms)
  end

  #
  # An instance of a Locale class that is associated with this module.
  #
  attr_reader :locale
  #
  # The module's major major version number (X.x.x.x).
  #
  attr_reader :maj_maj_ver
  #
  # The module's major minor version number (x.X.x.x).
  #
  attr_reader :maj_min_ver
  #
  # The module's minor major version number (x.x.X.x).
  #
  attr_reader :min_maj_ver
  #
  # The module's minor minor version number (x.x.x.X).
  #
  attr_reader :min_min_ver
  #
  # The timestamp that the image was compiled (as a Time instance).
  #
  attr_reader :timestamp
  #
  # The vendor that created the module.
  #
  attr_reader :vendor
  #
  # The preferred base address at which the module will load.
  #
  attr_reader :base_address
  #
  # The size of the image mapping associated with the module in bytes.
  #
  attr_reader :image_size
  #
  # An array of Segment instances.
  #
  attr_reader :segments
  #
  # An array of Import instances.
  #
  attr_reader :imports
  #
  # An array of Export instances.
  #
  attr_reader :exports
  #
  # An array of OsVersion instances.
  #
  attr_reader :platforms
end

###
#
# This class contains information about a specific locale, such as English.
#
###
class Locale
  include DbEntry
  class <<self
    include Cachable
  end
end

###
#
# This class contains information about a platform (operating system) version.
#
###
class OsVersion
  include DbEntry

  class <<self
    include Cachable
    def hash_key(hash)
      hash['id'] + (hash['modules'] || '')
    end
  end

  def initialize(hash)
    super

    @modules = (hash['modules']) ? hash['modules'].to_i : 0
    @desc    = hash['desc']
    @arch    = hash['arch']
    @maj_ver = hash['maj_ver'].to_i
    @min_ver = hash['min_ver'].to_i
    @maj_patch_level = hash['maj_patch_level'].to_i
    @min_patch_level = hash['min_patch_level'].to_i
  end

  #
  # The number of modules that exist in this operating system version.
  #
  attr_reader :modules
  #
  # The operating system version description, such as Windows XP 5.2.0.0
  # (IA32).
  #
  attr_reader :desc
  #
  # The architecture that the operating system version runs on, such as IA32.
  #
  attr_reader :arch
  #
  # The major version of the operating system version.
  #
  attr_reader :maj_ver
  #
  # The minor version of the operating system version.
  #
  attr_reader :min_ver
  #
  # The major patch level of the operating system version, such as a service
  # pack.
  #
  attr_reader :maj_patch_level
  #
  # The minor patch level of the operating system version.
  #
  attr_reader :min_patch_level
end

###
#
# An opcode group (esp => eip).
#
###
class Group
  include DbEntry
  class <<self
    include Cachable
  end
end

###
#
# An opcode type (jmp esp).
#
###
class Type
  include DbEntry

  class <<self
    include Cachable
  end

  def initialize(hash)
    super

    @opcodes   = (hash['opcodes']) ? hash['opcodes'].to_i : 0
    @meta_type = MetaType.create(hash['meta_type']) if (hash['meta_type'])
    @group     = Group.create(hash['group']) if (hash['group'])
    @arch      = hash['arch']
  end

  #
  # The number of opcodes associated with this type, or 0 if this information
  # is not available.
  #
  attr_reader :opcodes
  #
  # An instance of the MetaType to which this opcode type belongs, or nil.
  #
  attr_reader :meta_type
  #
  # An instance of the Group to which this opcode type belongs, or nil.
  #
  attr_reader :group
  #
  # The architecture that this opcode type is associated with.
  #
  attr_reader :arch
end

###
#
# An opcode meta type (jmp reg).
#
###
class MetaType
  include DbEntry
  class <<self
    include Cachable
  end
end

###
#
# An opcode that has a specific address and is associated with one or more
# modules.
#
###
class Opcode
  include DbEntry

  def initialize(hash)
    super

    @address = hash['address'].to_i
    @type    = Type.create(hash['type'])
    @group   = @type.group
    @modules = hash['modules'].map { |ent|
      ImageModule.create(ent)
    } if (hash['modules'])

    @modules = [] unless(@modules)
  end

  #
  # The address of the opcode.
  #
  attr_reader :address
  #
  # The type of the opcode indicating which instruction is found at the
  # address.  This is an instance of the Type class.
  #
  attr_reader :type
  #
  # A Group instance that reflects the group to which the opcode type found
  # at the instance's address belongs.
  #
  attr_reader :group
  #
  # An array of ImageModule instances that show the modules that contain this
  # address.
  #
  attr_reader :modules
end

###
#
# Current statistics of the opcode database.
#
###
class Statistics
  def initialize(hash)
    @modules         = hash['modules'].to_i
    @opcodes         = hash['opcodes'].to_i
    @opcode_types    = hash['opcode_types'].to_i
    @platforms       = hash['platforms'].to_i
    @architectures   = hash['architectures'].to_i
    @module_segments = hash['module_segments'].to_i
    @module_imports  = hash['module_imports'].to_i
    @module_exports  = hash['module_exports'].to_i
    @last_update     = Time.at(hash['last_update'].to_i)
  end

  #
  # The number of modules found within the opcode database.
  #
  attr_reader :modules
  #
  # The number of opcodes supported by the opcode database.
  #
  attr_reader :opcodes
  #
  # The number of opcode types supported by the database.
  #
  attr_reader :opcode_types
  #
  # The number of platforms supported by the database.
  #
  attr_reader :platforms
  #
  # The number of architectures supported by the database.
  #
  attr_reader :architectures
  #
  # The number of module segments supported by the database.
  #
  attr_reader :module_segments
  #
  # The number of module imports supported by the database.
  #
  attr_reader :module_imports
  #
  # The number of module exports supported by the database.
  #
  attr_reader :module_exports
  #
  # The time at which the last database update occurred.
  #
  attr_reader :last_update
end

###
#
# This class implements a client interface to the Metasploit Opcode Database.
# It is intended to be used as a method of locating reliable return addresses
# given a set of executable files and a set of usable opcodes.
#
###
class Client

  DefaultServerHost = "www.metasploit.com"
  DefaultServerPort = 80
  DefaultServerUri  = "/users/opcode/msfopcode_server.cgi"

  #
  # Returns an instance of an initialized client that will use the supplied
  # server values.
  #
  def initialize(host = DefaultServerHost, port = DefaultServerPort, uri = DefaultServerUri)
    self.server_host = host
    self.server_port = port
    self.server_uri  = uri
  end

  #
  # Disables response parsing.
  #
  def disable_parse
    @disable_parse = true
  end

  #
  # Enables response parsing.
  #
  def enable_parse
    @disable_parse = false
  end

  #
  # Returns an array of MetaType instances.
  #
  def meta_types
    request('meta_types').map { |ent| MetaType.create(ent) }
  end

  #
  # Returns an array of Group instances.
  #
  def groups
    request('groups').map { |ent| Group.create(ent) }
  end

  #
  # Returns an array of Type instances.  Opcode types are specific opcodes,
  # such as a jmp esp.  Optionally, a filter hash can be passed to include
  # extra information in the results.
  #
  # Statistics (Bool)
  #
  # 	If this hash element is set to true, the number of opcodes currently in
  # 	the database of this type will be returned.
  #
  def types(filter = {})
    request('types', filter).map { |ent| Type.create(ent) }
  end

  #
  # Returns an array of OsVersion instances.  OS versions are associated with
  # a particular operating system release (including service packs).
  # Optionally, a filter hash can be passed to limit the number of results
  # returned.  If no filter hash is supplied, all results are returned.
  #
  # Names (Array)
  #
  # 	If this hash element is specified, only the operating systems that
  # 	contain one or more of the names specified will be returned.
  #
  # Statistics (Bool)
  #
  # 	If this hash element is set to true, the number of modules associated
  # 	with this matched operating system versions will be returned.
  #
  def platforms(filter = {})
    request('platforms', filter).map { |ent| OsVersion.create(ent) }
  end

  #
  # Returns an array of ImageModule instances.  Image modules are
  # version-specific, locale-specific, and operating system version specific
  # image files.  Modules have opcodes, segments, imports and exports
  # associated with them.  Optionally, a filter hash can be specified to
  # limit the number of results returned from the database.  If no filter
  # hash is supplied, all modules will be returned.
  #
  # LocaleNames (Array)
  #
  # 	This hash element limits results to one or more specific locale by name.
  #
  # PlatformNames (Array)
  #
  # 	This hash element limits results to one or more specific platform by
  # 	name.
  #
  # ModuleNames (Array)
  #
  # 	This hash element limits results to one or more specific module by name.
  #
  # Segments (Bool)
  #
  # 	If this hash element is set to true, the segments associated with each
  # 	resulting module will be returned by the server.
  #
  # Imports (Bool)
  #
  # 	If this hash element is set to true, the imports associated with each
  # 	resulting module will be returned by the server.
  #
  # Exports (Bool)
  #
  # 	If this hash element is set to true, the exports associated with each
  # 	resulting module will be returned by the server.
  #
  def modules(filter = {})
    request('modules', filter).map { |ent| ImageModule.create(ent) }
  end

  #
  # Returns an array of Locale instances that are supported by the server.
  #
  def locales
    request('locales').map { |ent| Locale.create(ent) }
  end

  #
  # Returns an array of Opcode instances that match the filter limitations
  # specified in the supplied filter hash.  If no filter hash is specified,
  # all opcodes will be returned (but are most likely going to be limited by
  # the server).  The filter hash limiters that can be specified are:
  #
  # ModuleNames (Array)
  #
  # 	This hash element limits results to one or more specific modules by
  # 	name.
  #
  # GroupNames (Array)
  #
  # 	This hash element limits results to one or more specific opcode group by
  # 	name.
  #
  # TypeNames (Array)
  #
  # 	This hash element limits results to one or more specific opcode type by
  # 	name.
  #
  # MetaTypeNames (Array)
  #
  # 	This hash element limits results to one or more specific opcode meta
  # 	type by name.
  #
  # LocaleNames (Array)
  #
  # 	Limits results to one or more specific locale by name.
  #
  # PlatformNames (Array)
  #
  # 	Limits reslts to one or more specific operating system version by name.
  #
  # Addresses (Array)
  #
  # 	Limits results to a specific set of addresses.
  #
  # Portable (Bool)
  #
  # 	If this hash element is true, opcode results will be limited to ones
  # 	that span more than one operating system version.
  #
  def search(filter = {})
    request('search', filter).map { |ent| Opcode.new(ent) }
  end

  #
  # Returns an instance of the Statistics class that holds information about
  # the server's database stats.
  #
  def statistics
    Statistics.new(request('statistics'))
  end

  #
  # These attributes convey information about the remote server and can be
  # changed in order to point it to a locate copy as necessary.
  #
  attr_accessor :server_host, :server_port, :server_uri

  #
  # Retrieves the last raw XML response to be processed.
  #
  attr_reader :last_xml

protected

  #
  # Transmits a request to the Opcode database server and translates the
  # response into a native general ruby datatype.
  #
  def request(method, opts = {})
    client  = Rex::Proto::Http::Client.new(server_host, server_port)

    begin

      # Create the CGI parameter list
      vars = { 'method' => method }

      opts.each_pair do |k, v|
        vars[k] = xlate_param(v)
      end

      client.set_config('uri_encode_mode' => 'none')

      # Initialize the request with the POST body.
      request = client.request_cgi(
        'method'    => 'POST',
        'uri'       => server_uri,
        'vars_post' => vars
      )

      # Send the request and grab the response.
      response = client.send_recv(request, 300)

      # Non-200 return code?
      if (response.code != 200)
        raise RuntimeError, "Invalid response received from server."
      end

      # Convert the return value to the native type.
      parse_response(response.body)
    rescue ::SocketError
      raise RuntimeError, "Could not communicate with the opcode service: #{$!.class} #{$!}"
    ensure
      client.close
    end
  end

  #
  # Translates a parameter into a flat CGI parameter string.
  #
  def xlate_param(v)
    if (v.kind_of?(Array))
      v.map { |ent|
        xlate_param(ent)
      }.join(',,')
    elsif (v.kind_of?(Hash))
      v.map { |k,v|
        "#{URI.escape(k)}:#{xlate_param(v)}" if (v)
      }.join(',,')
    else
      URI.escape(v.to_s)
    end
  end

  #
  # Translate the data type from a flat string to a ruby native type.
  #
  def parse_response(xml)
    @last_xml = xml

    if (!@disable_parse)
      source = REXML::Source.new(xml)
      doc    = REXML::Document.new

      REXML::Parsers::TreeParser.new(source, doc).parse

      translate_element(doc.root)
    end
  end

  #
  # Translate elements conveyed as data types.
  #
  def translate_element(element)
    case element.name
      when "Array"
        return element.elements.map { |child| translate_element(child) }
      when "Hash"
        hsh = {}

        element.each_element { |child|
          if (e = child.elements[1])
            v = translate_element(e)
          else
            v = child.text
          end

          hsh[child.attributes['name']] = v
        }

        return hsh
      else
        return element.text
    end
  end

end

end
end
end
