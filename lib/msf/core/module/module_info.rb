module Msf::Module::ModuleInfo
  #
  # CONSTANTS
  #

  # The list of options that support merging in an information hash.
  UpdateableOptions = [ "Name", "Description", "Alias", "PayloadCompat" ]

  #
  # Instance Methods
  #

  #
  # Returns the module's alias, if it has one.  Otherwise, the module's
  # name is returned.
  #
  def alias
    module_info['Alias']
  end

  #
  # Return the module's description.
  #
  def description
    module_info['Description']
  end

  #
  # Returns the disclosure date, if known.
  #
  def disclosure_date
    date_str = Date.parse(module_info['DisclosureDate'].to_s) rescue nil
  end

  #
  # Return the module's name from the module information hash.
  #
  def name
    module_info['Name']
  end


  #
  # Return the module's notes (including AKA and NOCVE descriptors).
  #
  def notes
    module_info['Notes']
  end

  protected

  #
  # Attributes
  #

  # @!attribute module_info
  attr_accessor :module_info

  #
  # Instance Methods
  #

  #
  # Register options with a specific owning class.
  #
  def info_fixups
    # Each reference should be an array consisting of two elements
    refs = module_info['References']
    if(refs and not refs.empty?)
      refs.each_index do |i|
        if !(refs[i].respond_to?('[]') and refs[i].length == 2)
          refs[i] = nil
        end
      end

      # Purge invalid references
      refs.delete(nil)
    end
  end

  #
  # Checks and merges the supplied key/value pair in the supplied hash.
  #
  def merge_check_key(info, name, val)
    if (self.respond_to?("merge_info_#{name.downcase}", true))
      eval("merge_info_#{name.downcase}(info, val)")
    else
      # If the info hash already has an entry for this name
      if (info[name])
        # If it's not an array, convert it to an array and merge the
        # two
        if (info[name].kind_of?(Array) == false)
          curr       = info[name]
          info[name] = [ curr ]
        end

        # If the value being merged is an array, add each one
        if (val.kind_of?(Array) == true)
          val.each { |v|
            if (info[name].include?(v) == false)
              info[name] << v
            end
          }
        # Otherwise just add the value
        elsif (info[name].include?(val) == false)
          info[name] << val
        end
      # Otherwise, just set the value equal if no current value
      # exists
      else
        info[name] = val
      end
    end
  end

  #
  # Merges options in the info hash in a sane fashion, as some options
  # require special attention.
  #
  def merge_info(info, opts)
    opts.each_pair { |name, val|
      merge_check_key(info, name, val)
    }

    info
  end

  #
  # Merges advanced options.
  #
  def merge_info_advanced_options(info, val)
    merge_info_options(info, val, true, false)
  end

  #
  # Merge aliases with an underscore delimiter.
  #
  def merge_info_alias(info, val)
    merge_info_string(info, 'Alias', val, '_')
  end

  #
  # Merges the module description.
  #
  def merge_info_description(info, val)
    merge_info_string(info, 'Description', val, ". ", true)
  end

  #
  # Merges advanced options.
  #
  def merge_info_evasion_options(info, val)
    merge_info_options(info, val, false, true)
  end

  #
  # Merges the module name.
  #
  def merge_info_name(info, val)
    merge_info_string(info, 'Name', val, ', ', true)
  end

  #
  # Merges options.
  #
  def merge_info_options(info, val, advanced = false, evasion = false)

    key_name = ((advanced) ? 'Advanced' : (evasion) ? 'Evasion' : '') + 'Options'

    new_cont = Msf::OptionContainer.new
    new_cont.add_options(val, advanced, evasion)
    cur_cont = Msf::OptionContainer.new
    cur_cont.add_options(info[key_name] || [], advanced, evasion)

    new_cont.each_option { |name, option|
      next if (cur_cont.get(name))

      info[key_name]  = [] if (!info[key_name])
      info[key_name] << option
    }
  end

  #
  # Merges a given key in the info hash with a delimiter.
  #
  def merge_info_string(info, key, val, delim = ', ', inverse = false)
    if (info[key])
      if (inverse == true)
        info[key] = info[key] + delim + val
      else
        info[key] = val + delim + info[key]
      end
    else
      info[key] = val
    end
  end

  #
  # Merge the module version.
  #
  def merge_info_version(info, val)
    merge_info_string(info, 'Version', val)
  end

  #
  # Updates information in the supplied info hash and merges other
  # information.  This method is used to override things like Name, Version,
  # and Description without losing the ability to merge architectures,
  # platforms, and options.
  #
  def update_info(info, opts)
    opts.each_pair { |name, val|
      # If the supplied option name is one of the ones that we should
      # override by default
      if (UpdateableOptions.include?(name) == true)
        # Only if the entry is currently nil do we use our value
        if (info[name] == nil)
          info[name] = val
        end
      # Otherwise, perform the merge operation like normal
      else
        merge_check_key(info, name, val)
      end
    }

    return info
  end
end
