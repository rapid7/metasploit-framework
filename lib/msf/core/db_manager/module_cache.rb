#
# Standard library
#

require 'shellwords'

module Msf::DBManager::ModuleCache
  #
  # Attributes
  #

  # Flag to indicate that modules are cached
  attr_accessor :modules_cached

  # Flag to indicate that the module cacher is running
  attr_accessor :modules_caching

  #
  # Instance Methods
  #

  # Wraps values in +'%'+ for Arel::Prediciation#matches_any and other match* methods that map to SQL +'LIKE'+ or
  # +'ILIKE'+
  #
  # @param values [Set<String>, #each] a list of strings.
  # @return [Arrray<String>] strings wrapped like %<string>%
  def match_values(values)
    values.collect { |value| "%#{value}%" }
  end

  def module_to_details_hash(m)
    res  = {}
    bits = []

    res[:mtime]    = ::File.mtime(m.file_path) rescue Time.now
    res[:file]     = m.file_path
    res[:mtype]    = m.type
    res[:name]     = m.name.to_s
    res[:refname]  = m.refname
    res[:fullname] = m.fullname
    res[:rank]     = m.rank.to_i
    res[:license]  = m.license.to_s

    res[:description] = m.description.to_s.strip

    m.arch.map{ |x|
      bits << [ :arch, { :name => x.to_s } ]
    }

    m.platform.platforms.map{ |x|
      bits << [ :platform, { :name => x.to_s.split('::').last.downcase } ]
    }

    m.author.map{|x|
      bits << [ :author, { :name => x.to_s } ]
    }

    m.references.map do |r|
      bits << [ :ref, { :name => [r.ctx_id.to_s, r.ctx_val.to_s].join("-") } ]
    end

    res[:privileged] = m.privileged?


    if m.disclosure_date
      begin
        res[:disclosure_date] = m.disclosure_date.to_datetime.to_time
      rescue ::Exception
        res.delete(:disclosure_date)
      end
    end

    if(m.type == "exploit")

      m.targets.each_index do |i|
        bits << [ :target, { :index => i, :name => m.targets[i].name.to_s } ]
        if m.targets[i].platform
          m.targets[i].platform.platforms.each do |name|
            bits << [ :platform, { :name => name.to_s.split('::').last.downcase } ]
          end
        end
        if m.targets[i].arch
          bits << [ :arch, { :name => m.targets[i].arch.to_s } ]
        end
      end

      if (m.default_target)
        res[:default_target] = m.default_target
      end

      # Some modules are a combination, which means they are actually aggressive
      res[:stance] = m.stance.to_s.index("aggressive") ? "aggressive" : "passive"


      m.class.mixins.each do |x|
         bits << [ :mixin, { :name => x.to_s } ]
      end
    end

    if(m.type == "auxiliary")

      m.actions.each_index do |i|
        bits << [ :action, { :name => m.actions[i].name.to_s } ]
      end

      if (m.default_action)
        res[:default_action] = m.default_action.to_s
      end

      res[:stance] = m.passive? ? "passive" : "aggressive"
    end

    res[:bits] = bits.uniq

    res
  end

  # @note Does nothing unless {#migrated} is +true+ and {#modules_caching} is
  #   +false+.
  #
  # Destroys all Mdm::Module::Details in the database.
  #
  # @return [void]
  def purge_all_module_details
    return if not self.migrated
    return if self.modules_caching

    ::ActiveRecord::Base.connection_pool.with_connection do
      Mdm::Module::Detail.destroy_all
    end
  end

  # Destroys Mdm::Module::Detail if one exists for the given
  # Mdm::Module::Detail#mtype and Mdm::Module::Detail#refname.
  #
  # @param mtype [String] module type.
  # @param refname [String] module reference name.
  # @return [void]
  def remove_module_details(mtype, refname)
    return if not self.migrated

    ActiveRecord::Base.connection_pool.with_connection do
      Mdm::Module::Detail.where(:mtype => mtype, :refname => refname).destroy_all
    end
  end

  # This provides a standard set of search filters for every module.
  #
  # Supported keywords with the format <keyword>:<search_value>:
  # +author+:: Matches modules with the given author email or name.
  # +bid+:: Matches modules with the given Bugtraq ID.
  # +cve+:: Matches modules with the given CVE ID.
  # +edb+:: Matches modules with the given Exploit-DB ID.
  # +name+:: Matches modules with the given full name or name.
  # +os+, +platform+:: Matches modules with the given platform or target name.
  # +ref+:: Matches modules with the given reference ID.
  # +type+:: Matches modules with the given type.
  #
  # Any text not associated with a keyword is matched against the description,
  # the full name, and the name of the module; the name of the module actions;
  # the name of the module archs; the name of the module authors; the name of
  # module platform; the module refs; or the module target.
  #
  # @param search_string [String] a string of space separated keyword pairs or
  #   free form text.
  # @return [[]] if search_string is +nil+
  # @return [ActiveRecord::Relation] module details that matched
  #   +search_string+
  def search_modules(search_string)
    search_string ||= ''
    search_string += " "

    # Split search terms by space, but allow quoted strings
    terms = Shellwords.shellwords(search_string)
    terms.delete('')

    # All terms are either included or excluded
    value_set_by_keyword = Hash.new { |hash, keyword|
      hash[keyword] = Set.new
    }

    terms.each do |term|
      keyword, value = term.split(':', 2)

      unless value
        value = keyword
        keyword = 'text'
      end

      unless value.empty?
        keyword.downcase!

        value_set = value_set_by_keyword[keyword]
        value_set.add value
      end
    end

    ActiveRecord::Base.connection_pool.with_connection do
      @query = Mdm::Module::Detail.all

      @archs    = Set.new
      @authors  = Set.new
      @names    = Set.new
      @os       = Set.new
      @refs     = Set.new
      @text     = Set.new
      @types    = Set.new

      value_set_by_keyword.each do |keyword, value_set|
        formatted_values = match_values(value_set)

        case keyword
          when 'arch'
            @archs << formatted_values
          when 'author'
            @authors << formatted_values
          when 'name'
            @names << formatted_values
          when 'os', 'platform'
            @os << formatted_values
          when 'ref'
            @refs << formatted_values
          when 'cve', 'bid', 'edb'
            formatted_values = value_set.collect { |value|
              prefix = keyword.upcase
              "#{prefix}-%#{value}%"
            }
            @refs << formatted_values
          when 'text'
            @text << formatted_values
          when 'type'
            @types << formatted_values
        end
      end
    end

    @query = @query.module_arch(            @archs.to_a.flatten   ) if @archs.any?
    @query = @query.module_author(          @authors.to_a.flatten ) if @authors.any?
    @query = @query.module_name(            @names.to_a.flatten   ) if @names.any?
    @query = @query.module_os_or_platform(  @os.to_a.flatten      ) if @os.any?
    @query = @query.module_text(            @text.to_a.flatten    ) if @text.any?
    @query = @query.module_type(            @types.to_a.flatten   ) if @types.any?
    @query = @query.module_ref(             @refs.to_a.flatten    ) if @refs.any?

    @query.uniq
  end

  # Destroys the old Mdm::Module::Detail and creates a new Mdm::Module::Detail for
  # any module with an Mdm::Module::Detail where the modification time of the
  # Mdm::Module::Detail#file differs from the Mdm::Module::Detail#mtime.  If the
  # Mdm::Module::Detail#file no only exists on disk, then the Mdm::Module::Detail
  # is just destroyed without a new one being created.
  #
  # @return [void]
  def update_all_module_details
    return if not self.migrated
    return if self.modules_caching

    self.framework.cache_thread = Thread.current

    self.modules_cached  = false
    self.modules_caching = true

    ActiveRecord::Base.connection_pool.with_connection do

      refresh = []
      skip_reference_name_set_by_module_type = Hash.new { |hash, module_type|
        hash[module_type] = Set.new
      }

      Mdm::Module::Detail.find_each do |md|

        unless md.ready
          refresh << md
          next
        end

        unless md.file and ::File.exist?(md.file)
          refresh << md
          next
        end

        if ::File.mtime(md.file).to_i != md.mtime.to_i
          refresh << md
          next
        end

        skip_reference_name_set = skip_reference_name_set_by_module_type[md.mtype]
        skip_reference_name_set.add(md.refname)
      end

      refresh.each { |md| md.destroy }

      [
          ['exploit', framework.exploits],
          ['auxiliary', framework.auxiliary],
          ['post', framework.post],
          ['payload', framework.payloads],
          ['encoder', framework.encoders],
          ['nop', framework.nops]
      ].each do |mt|
        skip_reference_name_set = skip_reference_name_set_by_module_type[mt[0]]

        mt[1].keys.sort.each do |mn|
          next if skip_reference_name_set.include? mn
          obj = mt[1].create(mn)
          next if not obj
          begin
            update_module_details(obj)
          rescue ::Exception
            elog("Error updating module details for #{obj.fullname}: #{$!.class} #{$!}")
          end
        end
      end

      self.framework.cache_initialized = true
    end

    # in reverse order of section before with_connection block
    self.modules_caching = false
    self.modules_cached  = true
    self.framework.cache_thread = nil
  end

  # Creates an Mdm::Module::Detail from a module instance.
  #
  # @param module_instance [Msf::Module] a metasploit module instance.
  # @raise [ActiveRecord::RecordInvalid] if Hash from {#module_to_details_hash} is invalid attributes for
  #   Mdm::Module::Detail.
  # @return [void]
  def update_module_details(module_instance)
    return if not self.migrated

    ActiveRecord::Base.connection_pool.with_connection do
      info = module_to_details_hash(module_instance)
      bits = info.delete(:bits) || []
      module_detail = Mdm::Module::Detail.create!(info)

      bits.each do |args|
        otype, vals = args

        case otype
          when :action
            module_detail.add_action(vals[:name])
          when :arch
            module_detail.add_arch(vals[:name])
          when :author
            module_detail.add_author(vals[:name], vals[:email])
          when :platform
            module_detail.add_platform(vals[:name])
          when :ref
            module_detail.add_ref(vals[:name])
          when :target
            module_detail.add_target(vals[:index], vals[:name])
        end
      end

      module_detail.ready = true
      module_detail.save!
    end
  end
end
