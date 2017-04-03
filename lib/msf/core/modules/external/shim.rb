# -*- coding: binary -*-
require 'msf/core/modules/external'
require 'msf/core/modules/external/bridge'

class Msf::Modules::External::Shim
  def self.generate(module_path)
    mod = Msf::Modules::External::Bridge.new(module_path)
    return '' unless mod.meta
    case mod.meta['type']
    when 'remote_exploit.cmd_stager.wget'
      s = remote_exploit_cmd_stager(mod)
      File.open('/tmp/module', 'w') {|f| f.write(s)}
      s
    end
  end

  def self.remote_exploit_cmd_stager(mod)
    %Q|
require 'msf/core/modules/external/bridge'

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::CmdStager

  def initialize(info = {})
    super(update_info(info,
      'Name'        => #{mod.meta['name'].dump},
      'Description' => #{mod.meta['description'].dump},
      'Author'      =>
        [
          #{mod.meta['authors'].map(&:dump).join(', ')}
        ],
      'License'     => MSF_LICENSE,
      'References'  =>
        [
          #{mod.meta['references'].map do |r|
              "[#{r['type'].upcase.dump}, #{r['ref'].dump}]"
            end.join(', ')}
        ],
      'DisclosureDate' => #{mod.meta['date'].dump},
      'Privileged'     => #{mod.meta['privileged'].inspect},
      'Platform'       => [#{mod.meta['targets'].map{|t| t['platform'].dump}.uniq.join(', ')}],
      'Payload'        =>
        {
          'DisableNops' => true
        },
      'Targets'        =>
        [
          #{mod.meta['targets'].map do |t|
            %Q^[#{t['platform'].dump} + ' ' + #{t['arch'].dump},
                 {'Arch' => ARCH_#{t['arch'].upcase}, 'Platform' => #{t['platform'].dump} }]^
            end.join(', ')}
        ],
      'DefaultTarget'   => 0,
      'DefaultOptions' => { 'WfsDelay' => 5 }
      ))

      register_options([
        #{mod.meta['options'].map do |n, o|
            "Opt#{o['type'].capitalize}.new(#{n.dump},
              [#{o['required']}, #{o['description'].dump}, #{o['default'].inspect}])"
          end.join(', ')}
      ], self.class)
  end

  def execute_command(cmd, opts)
    mod = Msf::Modules::External::Bridge.new(#{mod.path.dump})
    mod.run(datastore.merge(command: cmd))
    wait_status(mod)
    true
  end

  def exploit
    print_status("Exploiting...")
    execute_cmdstager({:flavor  => :wget})
  end

  def wait_status(mod)
    while mod.running
      m = mod.get_status
      if m
        case m['level']
        when 'error'
          print_error m['message']
        when 'warning'
          print_warning m['message']
        when 'good'
          print_good m['message']
        when 'info'
          print_status m['message']
        when 'debug'
          vprint_status m['message']
        else
          print_status m['message']
        end
      end
    end
  end
end
    |
  end
end
