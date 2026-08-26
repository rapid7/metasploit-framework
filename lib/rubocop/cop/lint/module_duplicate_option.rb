# frozen_string_literal: true

module RuboCop
  module Cop
    module Lint
      # Detects options registered by a mixin that are registered again without
      # providing a more specific description. Use DefaultOptions to change only
      # the value of an inherited option.
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
        extend AutoCorrector
        include RangeHelp

        MIXIN_OPTIONS = {
          'Msf::Auxiliary::Scanner' => {
            'RHOSTS' => { default: nil, description: 'The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html' },
            'THREADS' => { default: 1, description: 'The number of concurrent threads (max one per host)' }
          },
          'Msf::Exploit::Remote::HttpClient' => {
            'RHOST' => { default: nil, description: 'The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html' },
            'RPORT' => { default: 80, description: 'The target port' },
            'VHOST' => { default: nil, description: 'HTTP server virtual host' },
            'SSL' => { default: false, description: 'Negotiate SSL/TLS for outgoing connections' },
            'Proxies' => { default: nil, description: nil }
          },
          'Msf::Exploit::Remote::Tcp' => {
            'RHOST' => { default: nil, description: 'The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html' },
            'RPORT' => { default: nil, description: 'The target port' }
          },
          'Msf::Exploit::Remote::Udp' => {
            'RHOST' => { default: nil, description: 'The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html' },
            'RPORT' => { default: nil, description: 'The target port' }
          }
        }.freeze

        MSG = 'Do not register the pre-existing %<option>s option again; set its value in DefaultOptions instead.'

        def on_class(class_node)
          return unless class_node.identifier&.const_name == 'MetasploitModule'

          inherited_options = inherited_options(class_node)
          return if inherited_options.empty?

          offenses = class_node.each_descendant(:send).select { |node| node.method?(:register_options) }.flat_map do |register_node|
            option_nodes(register_node).filter_map do |option_node|
              option_name = option_name(option_node)
              next unless inherited_options.key?(option_name)
              next unless description_unchanged?(option_node, inherited_options[option_name][:description])
              next if deregistered_before?(class_node, register_node, option_name)

              [option_node, option_name, inherited_options[option_name]]
            end
          end

          offenses.each_with_index do |(option_node, option_name, _option), index|
            add_offense(option_node, message: format(MSG, option: option_name)) do |corrector|
              autocorrect(corrector, class_node, offenses) if index.zero?
            end
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

        def description_unchanged?(node, inherited_description)
          description = if node.receiver&.const_name == 'Opt'
                          node.arguments[2]
                        elsif node.method?(:new)
                          node.arguments[1]&.values&.[](1)
                        end

          description.nil? || description.nil_type? || (description.str_type? && description.value == inherited_description)
        end

        def autocorrect(corrector, class_node, offenses)
          defaults = offenses.filter_map do |option_node, option_name, inherited_option|
            default_node = option_default(option_node)
            next if same_default?(default_node, inherited_option[:default])

            [option_name, { source: default_node&.source || 'nil', comment: trailing_comment(option_node) }]
          end.to_h

          info_hash = info_hash(class_node)
          return if defaults.any? && info_hash.nil?

          offenses.map(&:first).group_by { |option_node| option_node.each_ancestor(:send).find { |node| node.method?(:register_options) } }.each do |register_node, option_nodes|
            remove_options(corrector, register_node, option_nodes)
          end
          add_defaults(corrector, info_hash, defaults) if defaults.any?
        end

        def trailing_comment(node)
          source = node.source_range.source_buffer.source
          line_end = source.index("\n", node.source_range.end_pos) || source.length
          source[node.source_range.end_pos...line_end][/#.*$/]
        end

        def option_default(node)
          if node.receiver&.const_name == 'Opt'
            node.first_argument
          elsif node.method?(:new)
            node.arguments[1]&.values&.[](2)
          end
        end

        def same_default?(node, inherited_default)
          return inherited_default.nil? if node.nil? || node.nil_type?

          node.respond_to?(:value) && node.value == inherited_default
        end

        def info_hash(class_node)
          update_info = class_node.each_descendant(:send).find { |node| node.method?(:update_info) || node.method?(:merge_info) }
          hash = update_info&.arguments&.find(&:hash_type?)
          return hash if hash

          initialize_node = class_node.each_descendant(:def).find { |node| node.method_name == :initialize }
          super_node = initialize_node&.each_descendant(:super)&.first
          super_node&.arguments&.find(&:hash_type?)
        end

        def remove_options(corrector, register_node, removed_nodes)
          array = register_node.first_argument
          remaining_nodes = array&.array_type? ? array.values - removed_nodes : []
          if remaining_nodes.empty?
            remove_expression(corrector, register_node)
          else
            removed_nodes.each { |node| remove_array_element(corrector, node) }
          end
        end

        def remove_expression(corrector, node)
          range = node.source_range
          source = range.source_buffer.source
          begin_pos = source.rindex("\n", range.begin_pos - 1)&.+(1) || range.begin_pos
          previous_line_begin = source.rindex("\n", begin_pos - 2)&.+(1) || 0
          begin_pos = previous_line_begin if source[previous_line_begin...begin_pos].strip.empty?
          end_pos = source.index("\n", range.end_pos)&.+(1) || range.end_pos
          corrector.remove(range_between(begin_pos, end_pos))
        end

        def remove_array_element(corrector, node)
          siblings = node.parent.values
          next_node = siblings[siblings.index(node) + 1]
          if next_node
            corrector.remove(range_between(node.source_range.begin_pos, next_node.source_range.begin_pos))
          else
            previous_node = siblings[siblings.index(node) - 1]
            corrector.remove(range_between(previous_node.source_range.end_pos, node.source_range.end_pos))
          end
        end

        def add_defaults(corrector, hash, defaults)
          default_pair = hash.pairs.find { |pair| pair.key.str_type? && pair.key.value == 'DefaultOptions' }
          if default_pair&.value&.hash_type?
            merge_defaults(corrector, default_pair.value, defaults)
          else
            first_pair = hash.pairs.first
            unless first_pair
              indent = hash.source_range.column + 2
              entries = default_entries(defaults, indent + 2)
              corrector.insert_after(hash.loc.begin, "\n#{' ' * indent}'DefaultOptions' => {\n#{entries}\n#{' ' * indent}}\n#{' ' * (indent - 2)}")
              return
            end

            indent = first_pair.source_range.column
            entries = default_entries(defaults, indent + 2)
            corrector.insert_before(first_pair, "'DefaultOptions' => {\n#{entries}\n#{' ' * indent}},\n#{' ' * indent}")
          end
        end

        def merge_defaults(corrector, hash, defaults)
          existing = hash.pairs.filter_map { |pair| [pair.key.value, pair] if pair.key.str_type? }.to_h
          missing = []
          defaults.each do |name, value|
            if existing[name]
              corrector.replace(existing[name].value, value[:source])
              corrector.insert_before(existing[name], "#{value[:comment]}\n#{' ' * existing[name].source_range.column}") if value[:comment]
            else
              missing << [name, value]
            end
          end
          return if missing.empty?

          last_pair = hash.pairs.last
          if last_pair
            if hash.single_line?
              comments = missing.filter_map { |_name, value| value[:comment] }
              if comments.any?
                default_pair = hash.parent
                indent = default_pair.source_range.column
                corrector.insert_before(default_pair, "#{comments.join("\n#{' ' * indent}")}\n#{' ' * indent}")
              end
              entries = missing.map { |name, value| "'#{name}' => #{value[:source]}" }.join(', ')
              corrector.insert_after(last_pair, ", #{entries}")
              return
            end

            indent = last_pair.source_range.column
            entries = default_entries(missing.to_h, indent)
            corrector.insert_after(last_pair, ",\n#{entries}")
          else
            indent = hash.source_range.column + 2
            entries = default_entries(missing.to_h, indent)
            corrector.insert_after(hash.loc.begin, "\n#{entries}\n#{' ' * (indent - 2)}")
          end
        end

        def default_entries(defaults, indent)
          defaults.map do |name, value|
            comment = value[:comment] ? "#{' ' * indent}#{value[:comment]}\n" : ''
            "#{comment}#{' ' * indent}'#{name}' => #{value[:source]}"
          end.join(",\n")
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
