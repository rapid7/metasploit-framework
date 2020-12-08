# -*- coding: binary -*-

require 'rex/parser/graphml'
require 'rex/arch'
##
# This module contains a helper function for generating payloads from a shuffled
# set of instructions loaded from a special file.
##
module Rex
  module Payloads
    class Shuffle

      FLOW_INSTRUCTIONS = {}
      FLOW_INSTRUCTIONS[Rex::Arch::ARCH_X86] = %w{ call jae jb jbe jc jcxz je jecxz jg jge jl jle jmp jna jnae jnb jnbe jnc jne jng jnge jnl jnle jno jnp jns jnz jo jp jpe jpo js jz }.freeze
      FLOW_INSTRUCTIONS[Rex::Arch::ARCH_X64] = (FLOW_INSTRUCTIONS[Rex::Arch::ARCH_X86] + %w{ jrcxz }).freeze

      #
      # Shuffle instructions from a GraphML data file and return the assembly source. If an architecture is specified
      # and supported, labels will be added for control flow instructions such as jumps and calls. Labels are necessary
      # if any post processing is performed on the source (such as for obfuscation).
      #
      # @param file_path [String] The file path to load the GraphML data from.
      # @param name [String] An optional symbol name to apply to the assembly source.
      def self.from_graphml_file(file_path, arch: nil, name: nil)
        graphml = Rex::Parser::GraphML.from_file(file_path)
        blocks = graphml.graphs.select { |graph| graph.attributes['type'] == 'block' }.sort_by { |graph| graph.attributes['address'] }
        blocks.map! { |block| { node: block, instructions: self.process_block(block) } }

        label_prefix = Rex::Text.rand_text_alpha_lower(4)
        labeler = lambda { |address| "loc_#{label_prefix}#{ address.to_s(16).rjust(4, '0') }" }

        source_lines = []
        labeled = []
        label_refs = []
        blocks.each do |block|
          source_lines << labeler.call(block[:node].attributes['address']) + ':'
          labeled << block[:node].attributes['address']
          # by default use the raw binary instruction to avoid syntax compatibility issues with metasm
          instructions = block[:instructions].map { |node| 'db ' + node.attributes['instruction.hex'].strip.chars.each_slice(2).map { |hex| '0x' + hex.join }.join(', ') }
          unless arch.nil?
            raise ArgumentError, 'Unsupported architecture' if FLOW_INSTRUCTIONS[arch].nil?

            # if a supported architecture was specified, use the original source and apply the necessary labels
            block[:instructions].each_with_index do |node, index|
              next unless match = /^(?<mnemonic>\S+)\s+(?<address>0x[a-f0-9]+)$/.match(node.attributes['instruction.source'])
              next unless FLOW_INSTRUCTIONS[arch].include? match[:mnemonic]

              address = Integer(match[:address])
              instructions[index] = "#{match[:mnemonic]} #{labeler.call(address)}"
              label_refs << address
            end
          end

          source_lines += instructions
        end

        unless label_refs.all? { |address| labeled.include? address  }
          # raise this here so it's closer to the source of the problem :(
          raise StandardError, 'Missing label reference'
        end


        source_lines = ([name + ':'] + source_lines.map { |source_line| '  ' + source_line}) unless name.nil?
        source_lines.join("\n") + "\n"
      end

      private

      #
      # Process the specified graph element which represents a single basic block in assembly. This graph element
      # contains nodes representing each of its instructions.
      #
      def self.process_block(block)
        path = []
        instructions = block.nodes.select { |_id, node| node.attributes['type'] == 'instruction' }

        # the initial choices are any node without a predecessor (dependency)
        targets = block.edges.map(&:target)
        choices = instructions.values.select { |node| !targets.include? node.id }
        until choices.empty?
          selection = choices.sample
          choices.delete(selection)
          path << selection

          # check each node for which the selection is a dependency
          successors = selection.target_edges.map { |edge| instructions[edge.target] }
          successors.each do |successor|
            next if path.include? successor
            next if !successor.source_edges.map { |edge| path.include? instructions[edge.source] }.all?

            choices << successor
          end
        end

        path
      end

    end
  end
end
