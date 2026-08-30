# -*- coding: binary -*-
# rubocop:disable Metrics/AbcSize
# rubocop:disable Metrics/ClassLength
# rubocop:disable Metrics/CyclomaticComplexity
module Msf
  module Serializer
    #
    # This class formats information in a json format that
    # is meant to be displayed on a console or some other non-GUI
    # medium.
    class Json
      #
      # Returns a formatted string that contains information about
      # the supplied module instance.
      #
      # @param mod [Msf::Module] the module to dump information for.
      # @param _indent [String] the indentation to use.
      # @return [String] formatted text output of the dump.
      def self.dump_module(mod, _indent = "")
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
          return dump_basic_module(mod)
        end
      end

      # Dumps an exploit's targets.
      #
      # @param mod [Msf::Exploit] the exploit module to dump targets
      #   for.
      # @return [Array] the exploit targets
      def self.dump_exploit_targets(mod)
        list = []

        mod.targets.each { |target| list.push(target.name || 'All') }

        list
      end

      # Dumps a module's actions
      #
      # @param mod [Msf::Module] the module.
      # @return [Array] the module actions
      def self.dump_module_actions(mod)
        list = []

        mod.actions.each do |target|
          list.push('name' => (target.name || 'All'),
                    'description' => (target.description || ''))
        end

        list
      end

      # Dumps the module's selected action
      #
      # @param mod [Msf::Module] the module.
      # @return [Array] the module options
      def self.dump_module_action(mod)
        list = []

        list.push('name' => (mod.action.name || 'All'),
                  'description' => (mod.action.description || ''))

        list
      end

      # Dumps information common to all modules
      def self.dump_common_module_info(mod)
        {
          'name' => mod.name,
          'fullname' => mod.fullname,
          'authors' => dump_authors(mod),
          'rank' => mod.rank_to_s.capitalize,
          'description' => Rex::Text.compress(mod.description),
          'options' => dump_options(mod)
        }
      end

      # Dumps information about an exploit module.
      #
      # @param mod [Msf::Exploit] the exploit module.
      # @return [String] the json string form of the information.
      def self.dump_exploit_module(mod)
        # Return a json dump of exploit module data
        {
          'platform' => mod.platform_to_s,
          'privileged' => (mod.privileged? ? "Yes" : "No"),
          'license' => mod.license,
          'disclosure_date' => (mod.disclosure_date if mod.disclosure_date),
          'payload' => {
            'space' => (mod.payload_space.to_s if mod.payload_space),
            'badchars' => (mod.payload_badchars.length.to_s if mod.payload_badchars)
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
          'license' => mod.license,
          'disclosure_date' => (mod.disclosure_date if mod.disclosure_date),
          'actions' => dump_module_actions(mod),
          'references' => dump_references(mod)
        }.merge(dump_common_module_info(mod)).to_json
      end

      # Dumps information about a post module.
      #
      # @param mod [Msf::Post] the post module.
      # @return [String] the string form of the information.
      def self.dump_post_module(mod)
        # Return a json dump of post module data
        {
          'platform' => mod.platform_to_s,
          'arch' => mod.arch_to_s,
          'disclosure_date' => (mod.disclosure_date if mod.disclosure_date),
          'actions' => dump_module_actions(mod),
          'references' => dump_references(mod)
        }.merge(dump_common_module_info(mod)).to_json
      end

      # Dumps information about a payload module.
      #
      # @param mod [Msf::Payload] the payload module.
      # @return [String] the string form of the information.
      def self.dump_payload_module(mod)
        # Return a json dump of post module data
        {
          'platform' => mod.platform_to_s,
          'arch' => mod.arch_to_s,
          'privileged' => (mod.privileged? ? "true" : "false"),
          'size' => mod.size
        }.merge(dump_common_module_info(mod)).to_json
      end

      # Returns an array of all authors
      #
      # @param mod [Msf::Module]
      # @return [Array] an array of all authors
      def self.dump_authors(mod)
        # Authors
        authors = []
        mod.each_author { |author| authors.push(author.to_s) }
        authors
      end

      # Dumps information about a module, just the basics.
      #
      # @param mod [Msf::Module] the module.
      # @return [String] the string form of the information.
      def self.dump_basic_module(mod)
        {
          'platform' => mod.platform_to_s,
          'arch' => mod.arch_to_s,
          'references' => dump_references(mod)
        }.merge(dump_common_module_info(mod)).to_json
      end

      # Dumps the list of options associated with the
      # supplied module.
      #
      # @param mod [Msf::Module] the module.
      # @return [Array] the array of the information.
      def self.dump_options(mod)
        list = []
        mod.options.sorted.each do |entry|
          name, opt = entry
          val = mod.datastore[name] || opt.default

          next if opt.advanced? || opt.evasion?

          list.push('name' => name,
                    'display_value' => opt.display_value(val),
                    'required' => opt.required? ? 'true' : 'false',
                    'description' => opt.desc.strip)
        end

        list
      end

      # Dumps the references associated with the supplied module.
      #
      # @param mod [Msf::Module] the module.
      # @return [Array] the array of the information.
      def self.dump_references(mod)
        if (mod.respond_to? :references) && mod.references && (mod.references.length > 0)
          refs = []
          mod.references.each { |ref| refs.push(ref.to_s) }
        end

        refs
      end
    end
  end
end
