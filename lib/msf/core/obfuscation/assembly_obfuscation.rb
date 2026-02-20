require 'metasploit/framework/obfuscation/assembly_obfuscator'
module Msf::Obfuscation::AssemblyObfuscation
  def initialize(info = {})
    super
    register_advanced_options(
      [
        Msf::OptBool.new('AssemblyObfuscation::Enable', [ false, 'Obfuscate the assembly instructions in the payload' ]),
        Msf::OptInt.new('AssemblyObfuscation::Passes', [ false, 'Number of obfuscation passes to applys', 1 ]),
        Msf::OptInt.new('AssemblyObfuscation::Percentual', [ false, 'Percentage of instructions to obfuscate (0-100)', 0 ])
      ], self.class
    )
  end

  def obfuscate_assembly(arch, assembly)
    if datastore['AssemblyObfuscation::Enable']
      passes = datastore['AssemblyObfuscation::Passes'] || 1
      percentual = datastore['AssemblyObfuscation::Percentual'] || 50
      if percentual == 100 && passes > 1
        print_warning("Obfuscation is set to 100%, so only one pass will be applied regardless of the number of passes specified.")
        passes = 1
      end
      obfuscator = Metasploit::Framework::Obfuscation::AssemblyObfuscator.new(assembly, arch: arch, percentual: percentual)
      assembly = obfuscator.obfuscate(passes)
    end
    assembly
  end
end