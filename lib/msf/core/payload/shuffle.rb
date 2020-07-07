# -*- coding: binary -*-

require 'rex/parser/graphml'

##
# This module contains a helper function for generating payloads from a shuffled
# set of instructions loaded from a special file.
##
module Msf::Payload::Shuffle
  #
  # Load constraint information from a GraphML file and then use it to shuffle the instructions. Constraints are
  # expected to be identified as edges between instruction nodes that define ordering precedence. Each instruction node
  # must specify it's instruction source and binary representation (encoded in hex).
  #
  # @param file_name [String] The name of the GraphML file to load.
  # @return [Array] The array of assembly instructions.
  def shuffle_instructions(file_name)
    file_path = File.join(Msf::Config.install_root, 'data', 'shellcode', file_name + '.graphml')
    graphml = Rex::Parser::GraphML.from_file(file_path)

    # build an array of all of the graphs representing basic blocks, sorted by their address
    blocks = graphml.graphs.filter { |graph| graph.attributes['type'] == 'block' }.sort_by { |graph| graph.attributes['address'] }
    blocks.map { |block| process_block(block) }.flatten
  end

  private

  #
  # Process the specified graph element which represents a single basic block in assembly. This graph element contains
  # nodes representing each of its instructions.
  #
  def process_block(block)
    path = []
    instructions = block.nodes.select { |_id, node| node.attributes['type'] == 'instruction' }

    # the initial choices are any node without a predecessor (dependency)
    targets = block.edges.map(&:target)
    choices = instructions.values.filter { |node| !targets.include? node.id }
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

    path.map { |node| 'db ' + node.attributes['instruction.hex'].strip.chars.each_slice(2).map { |hex| '0x' + hex.join }.join(', ') }
  end
end
