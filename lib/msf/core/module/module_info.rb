module Msf::Module::ModuleInfo
  #
  # CONSTANTS
  #

  # The list of options that don't support merging in an information hash.
  UpdateableOptions = ['Name', 'Description', 'Alias', 'PayloadCompat', 'Stance'].freeze

  # Reference types that can have 2 or 3 elements (e.g., GHSA with optional repo)
  ReferencesWithOptionalThirdElement = ['GHSA'].freeze

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
    # Each reference should be an array consisting of two or three elements
    refs = module_info['References']
    return unless refs&.any?

    refs.reject! do |ref|
      next true unless ref.respond_to?('[]') && !ref.empty?

      # Some reference types can have 2 or 3 elements (e.g., GHSA with optional repo)
      # Other references should have 2 elements
      ref_type = ref[0]
      can_have_third_element = ReferencesWithOptionalThirdElement.include?(ref_type)
      valid_length = can_have_third_element ? (ref.length == 2 || ref.length == 3) : (ref.length == 2)

      !valid_length
    end
  end

  #
  # Checks and merges the supplied key/value pair in the supplied hash.
  #
  def merge_check_key(info, name, val)
    merge_method = "merge_info_#{name.downcase}"
    return __send__(merge_method, info, val) if respond_to?(merge_method, true)

    return info[name] = val unless info[name]

    # Handle hash merging recursively
    if info[name].is_a?(Hash)
      raise TypeError, 'can only merge a hash into a hash' unless val.is_a?(Hash)
      val.each_pair { |val_key, val_val| merge_check_key(info[name], val_key, val_val) }
      return
    end

    # Convert to array if needed
    info[name] = Array(info[name]) unless info[name].is_a?(Array)

    # Merge values, avoiding duplicates
    values_to_add = val.is_a?(Array) ? val : [val]
    values_to_add.each { |v| info[name] << v unless info[name].include?(v) }
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
    key = 'Description'
    unless info[key]
      info[key] = val
      return
    end

    current_value = Msf::Serializer::ReadableText.word_wrap_description(info[key])
    new_value = Msf::Serializer::ReadableText.word_wrap_description(val)
    info[key] = current_value.end_with?('.') ? "#{current_value}\n#{val}" : "#{current_value}.\n\n#{new_value}"
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
    opts.each_pair do |name, val|
      # If the supplied option name is one of the ones that we should
      # override by default
      if UpdateableOptions.include?(name)
        # Only if the entry is currently nil do we use our value
        if info[name].nil?
          info[name] = val
        end
        # Otherwise, perform the merge operation like normal
      else
        merge_check_key(info, name, val)
      end
    end

    info
  end
end
