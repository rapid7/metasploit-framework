# frozen_string_literal: true

module RuboCop
  module Cop
    module Lint
      # Detects Opt helper calls that supply only a new default for an option
      # already registered by a mixin. Use the DefaultOptions metadata instead.
      #
      # @example
      #   # bad
      #   include Msf::Exploit::Remote::Tcp
      #
      #   register_options([Opt::RPORT(4840)])
      #
      #   # good
      #   include Msf::Exploit::Remote::Tcp
      #
      #   'DefaultOptions' => {
      #     'RPORT' => 4840
      #   }
      class ModuleDuplicateOption < Base
        MIXIN_OPTIONS = {
          'Msf::Auxiliary::Scanner' => {
            'RHOSTS' => nil
          },
          'Msf::Exploit::Remote::HttpClient' => {
            'RHOST' => nil,
            'RPORT' => 80,
            'Proxies' => nil
          },
          'Msf::Exploit::Remote::Tcp' => {
            'RHOST' => nil,
            'RPORT' => nil
          },
          'Msf::Exploit::Remote::Udp' => {
            'RHOST' => nil,
            'RPORT' => nil
          }
        }.freeze

        MSG = 'Do not register the pre-existing %<option>s option again; set its value in DefaultOptions instead.'

        def on_send(node)
          return unless node.method?(:register_options)

          class_node = node.each_ancestor(:class).first
          return unless class_node&.identifier&.const_name == 'MetasploitModule'

          inherited_options = inherited_options(class_node)
          return if inherited_options.empty?

          option_nodes(node).each do |option_node|
            option_name = option_name(option_node)
            next unless inherited_options.key?(option_name)
            next unless only_default_changed?(option_node, inherited_options[option_name])
            next if deregistered_before?(class_node, node, option_name)

            add_offense(option_node, message: format(MSG, option: option_name))
          end
        end

        private

        def inherited_options(class_node)
          included_mixins = class_node.each_descendant(:send).filter_map do |send_node|
            next unless send_node.method?(:include)

            send_node.first_argument&.const_name
          end

          MIXIN_OPTIONS.slice(*included_mixins).values.reduce({}, &:merge)
        end

        def option_nodes(register_node)
          argument = register_node.first_argument
          return [] unless argument

          argument.array_type? ? argument.values : [argument]
        end

        def option_name(node)
          return unless node.send_type?

          if node.receiver&.const_name == 'Opt'
            node.method_name.to_s
          elsif node.method?(:new) && node.first_argument&.str_type?
            node.first_argument.value
          end
        end

        def only_default_changed?(node, inherited_default)
          return false unless node.receiver&.const_name == 'Opt' && node.arguments.one?

          argument = node.first_argument
          !argument.respond_to?(:value) || argument.value != inherited_default
        end

        def deregistered_before?(class_node, register_node, option_name)
          class_node.each_descendant(:send).any? do |send_node|
            send_node.method?(:deregister_options) &&
              send_node.source_range.begin_pos < register_node.source_range.begin_pos &&
              send_node.arguments.any? { |argument| argument.str_type? && argument.value == option_name }
          end
        end
      end
    end
  end
end
