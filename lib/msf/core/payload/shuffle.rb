# -*- coding: binary -*-

require 'rex/parser/graphml'

##
# This module contains a helper function for generating payloads from a shuffled
# set of instructions loaded from a special file.
##
module Msf::Payload::Shuffle

  def shuffle_instructions(file_name)
    file_path = File.join(Msf::Config.install_root, 'data', 'shellcode', file_name + '.graphml')
    graphml = Rex::Parser::GraphML.parse(file_path)

    # build an array of all of the graphs representing basic blocks, sorted by their address
    blocks = graphml.graphs.filter { |graph| graph.attributes['type'] == 'block' }.sort_by { |graph| graph.attributes['address'] }
    blocks.map { |block| process_block(block) }.flatten
  end

  private

  def process_block(block)
    path = []
    instructions = block.nodes.select { |id,node| node.attributes['type'] == 'instruction' }

    # the initial choices are any node without a predecessor (dependency)
    targets = block.edges.map { |edge| edge.target }
    choices = instructions.values.filter { |node| !targets.include? node.id }
    while !choices.empty?
      selection = choices.sample
      choices.delete(selection)
      path << selection

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
