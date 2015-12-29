# -*- coding: binary -*-
module Msf
module Serializer

# This class formats information in a json format that
# is meant to be displayed on a console or some other non-GUI
# medium.
class Json

  #Default number of characters to wrap at.
  DefaultColumnWrap = 70
  #Default number of characters to indent.
  DefaultIndent     = 2

  # Returns a formatted string that contains information about
  # the supplied module instance.
  #
  # @param mod [Msf::Module] the module to dump information for.
  # @param indent [String] the indentation to use.
  # @return [String] formatted text output of the dump.
  def self.dump_module(mod, indent = "  ")
    case mod.type
      when Msf::MODULE_PAYLOAD
        return dump_payload_module(mod)
      when Msf::MODULE_NOP
        return dump_basic_module(mod)
      when Msf::MODULE_ENCODER
        return dump_basic_module(mod)
      when Msf::MODULE_EXPLOIT
        return dump_exploit_module(mod)
      when Msf::MODULE_AUX
        return dump_auxiliary_module(mod)
      when Msf::MODULE_POST
        return dump_post_module(mod)
      else
        return dump_generic_module(mod)
    end
  end

  # Dumps an exploit's targets.
  #
  # @param mod [Msf::Exploit] the exploit module to dump targets
  #   for.
  # @return [Array] the exploit targets
  def self.dump_exploit_targets(mod)
    list = []

    mod.targets.each_with_index { |target, idx|
      list.push(target.name || 'All')
    }

    list
  end

  # Dumps a module's actions
  #
  # @param mod [Msf::Module] the module.
  # @return [Array] the module actions
  def self.dump_module_actions(mod)
    list = []
      mod.actions.each_with_index { |target, idx|
        list.push('name' => (target.name || 'All') , 'description' => (target.description || ''))
    }

    list
  end

  # Dumps the module's selected action
  #
  # @param mod [Msf::Module] the module.
  # @return [Array] the module options
  def self.dump_module_action(mod)
    list = []

    list.push('name' => (mod.action.name || 'All'), 'description' => (mod.action.description || ''))

    list
  end

  # Dumps information common to all modules
  def self.dump_common_module_info(mod)
    {
      'Name' => mod.name,
      'Module' => mod.fullname,
      'Provided by' => dump_authors(mod),
      'Rank' => mod.rank_to_s.capitalize,
      'description' => Rex::Text.compress(mod.description),
      'Basic options' =>  dump_options(mod),
    }
  end

  # Dumps information about an exploit module.
  #
  # @param mod [Msf::Exploit] the exploit module.
  # @return [String] the json string form of the information.
  def self.dump_exploit_module(mod)
   # Return a json dump of exploit module data
    {
    'Platform' => mod.platform_to_s,
    'Privileged' => (mod.privileged? ? "Yes" : "No"),
    'License' => mod.license,
    'Disclosed' => (mod.disclosure_date if mod.disclosure_date),
    'Payload information'=> {
      'Space' => (mod.payload_space.to_s if mod.payload_space),
      'Avoid' => (mod.payload_badchars.length.to_s if mod.payload_badchars)
    },
    'references' => dump_references(mod)

    }.merge(dump_common_module_info(mod)).to_json
  end

  # Dumps information about an auxiliary module.
  #
  # @param mod [Msf::Auxiliary] the auxiliary module.
  # @return [String] the string form of the information.
  def self.dump_auxiliary_module(mod)
    # Return a json dump of auxiliary module data
    {
      'License' => mod.license,
      'Disclosed' => (mod.disclosure_date if mod.disclosure_date),
      'Available actions' => dump_module_actions(mod),
      'References' => dump_references(mod)
    }.merge(dump_common_module_info(mod)).to_json
  end

  # Dumps information about a post module.
  #
  # @param mod [Msf::Post] the post module.
  # @return [String] the string form of the information.
  def self.dump_post_module(mod)
    # Return a json dump of post module data
    {
      'Platform' => mod.platform_to_s,
      'Arch' => mod.arch_to_s,
      'Disclosed' => (mod.disclosure_date if mod.disclosure_date),
      'Available actions' => dump_module_actions(mod),
      'References' => dump_references(mod)
    }.merge(dump_common_module_info(mod)).to_json
  end

  # Dumps information about a payload module.
  #
  # @param mod [Msf::Payload] the payload module.
  # @return [String] the string form of the information.
  def self.dump_payload_module(mod)
    # Return a json dump of post module data
    {
      'Platform' => mod.platform_to_s,
      'Arch' => mod.arch_to_s,
      'Needs Admin' => (mod.privileged? ? "Yes" : "No"),
      'Total size' => mod.size,
    }.merge(dump_common_module_info(mod)).to_json

  end

  # Returns an array of all authors
  #
  # @param mod [Msf::Module]
  # @return [Array] an array of all authors
  def self.dump_authors(mod)
    # Authors
    authors = []
    mod.each_author { |author|
      authors.push(author.to_s)
    }
    authors
  end

  # Dumps information about a module, just the basics.
  #
  # @param mod [Msf::Module] the module.
  # @return [String] the string form of the information.
  def self.dump_basic_module(mod)
    {
      'Platform' => mod.platform_to_s,
      'Arch' => mod.arch_to_s,
      'References' => dump_references(mod)
    }.merge(dump_common_module_info(mod)).to_json
  end

  # Dumps the list of options associated with the
  # supplied module.
  #
  # @param mod [Msf::Module] the module.
  # @return [Array] the array of the information.
  def self.dump_options(mod)
    list = []
    mod.options.sorted.each { |entry|
      name, opt = entry
      val = mod.datastore[name] || opt.default

      next if (opt.advanced?)
      next if (opt.evasion?)
      next if (opt.valid?(val))

      list.push('name' => name, 'display_value' => opt.display_value(val), 'required' => opt.required? ? 'yes' : 'no', 'description' => opt.desc)
    }

    list
  end

  # Dumps the advanced options associated with the supplied module.
  #
  # @param mod [Msf::Module] the module.
  # @return [Array] the array of the information.
  def self.dump_advanced_options(mod)
    list = []
    mod.options.sorted.each { |entry|
      name, opt = entry

      next if (!opt.advanced?)

      val = mod.datastore[name] || opt.default.to_s

      list.push("Name" => name, "Current Setting" => val, "Description" => opt.desc)
    }
    list
  end

  # Dumps the evasion options associated with the supplied module.
  #
  # @param mod [Msf::Module] the module.
  # @return [Array] the array of the information.
  def self.dump_evasion_options(mod)
    list = []
    mod.options.sorted.each { |entry|
      name, opt = entry

      next if (!opt.evasion?)

      val = mod.datastore[name] || opt.default || ''

      list.push("Name" => name, "Current Setting" => val, "Description" => opt.desc)
    }

    list
  end

  # Dumps the references associated with the supplied module.
  #
  # @param mod [Msf::Module] the module.
  # @return [Array] the array of the information.
  def self.dump_references(mod)
    if (mod.respond_to? :references and mod.references and mod.references.length > 0)
      refs = []
      mod.references.each { |ref|
        refs.push(ref.to_s)
      }
    end
    refs
  end

end

end end

