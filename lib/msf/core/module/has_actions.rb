# -*- coding: binary -*-

module Msf::Module::HasActions
  def initialize(info={})
    super
    self.actions = Rex::Transformer.transform(
      info['Actions'], Array,
      [ Msf::Module::AuxiliaryAction ], 'AuxiliaryAction'
    )

    self.passive = (info['Stance'] and info['Stance'].include?(Msf::Exploit::Stance::Passive)) || false
    self.default_action = info['DefaultAction']
    self.passive_actions = info['PassiveActions'] || []
  end

  def action
    sa = find_action(datastore['ACTION'])
    return find_action(default_action) unless sa

    sa
  end

  def find_action(name)
    return nil if not name
    actions.each do |a|
      return a if a.name.downcase == name.downcase
    end
    return nil
  end

  #
  # Returns a boolean indicating whether this module should be run passively
  #
  def passive?
    act = action
    return passive || passive_action?(act.name) if act

    passive
  end

  #
  # Returns a boolean indicating whether this specific action should be run passively
  #
  def passive_action?(name)
    passive_actions.include?(name)
  end

  #
  # Allow access to the hash table of actions and the string containing
  # the default action
  #
  attr_reader :actions, :default_action, :passive, :passive_actions

protected
  attr_writer :actions, :default_action, :passive, :passive_actions
end
