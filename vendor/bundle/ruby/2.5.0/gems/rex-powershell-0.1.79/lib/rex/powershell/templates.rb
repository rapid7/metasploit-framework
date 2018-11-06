module Rex
  module Powershell
    module Templates

      # RandomIdentifier::Generator options
      DEFAULT_RIG_OPTS = Rex::Powershell::Script::DEFAULT_RIG_OPTS

      # The base directory that all Powershell script templates live in
      TEMPLATE_DIR = File.expand_path( File.join( __FILE__ , '..', '..', '..', '..', 'data', 'templates') )

      # The powershell script template for memory injection using .NET
      TO_MEM_DOTNET = File.join(TEMPLATE_DIR, 'to_mem_dotnet.ps1.template')

      # The powershell script template for memory injection using reflection
      TO_MEM_REFLECTION = File.join(TEMPLATE_DIR, 'to_mem_pshreflection.ps1.template')

      # The powershell script template for memory injection using the old method
      TO_MEM_OLD = File.join(TEMPLATE_DIR, 'to_mem_old.ps1.template')

      # The powershell script template for memory injection using the old method
      TO_MEM_MSIL = File.join(TEMPLATE_DIR, 'to_mem_msil.ps1.template')

    end
  end
end
