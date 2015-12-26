# -*- coding:binary -*-
require 'spec_helper'

require 'rex/powershell'

<<<<<<< HEAD:spec/lib/rex/powershell/function_spec.rb
RSpec.describe Rex::Powershell::Function do
=======
describe Rex::Powershell::Function do
>>>>>>> origin/chore/MSP-12110/celluloid-supervision-tree:spec/lib/rex/powershell/function_spec.rb

  let(:function_name) do
    Rex::Text.rand_text_alpha(15)
  end

  let(:example_function_without_params) do
    """
{
    ls HKLM:\SAM\SAM\Domains\Account\Users |
        where {$_.PSChildName -match \"^[0-9A-Fa-f]{8}$\"} |
            Add-Member AliasProperty KeyName PSChildName -PassThru |
            Add-Member ScriptProperty Rid {[Convert]::ToInt32($this.PSChildName, 16)} -PassThru |
            Add-Member ScriptProperty V {[byte[]]($this.GetValue(\"V\"))} -PassThru |
            Add-Member ScriptProperty UserName {Get-UserName($this.GetValue(\"V\"))} -PassThru |
            Add-Member ScriptProperty HashOffset {[BitConverter]::ToUInt32($this.GetValue(\"V\")[0x9c..0x9f],0) + 0xCC} -PassThru
}"""
  end

  let(:example_function_with_params) do
    """
    {
        Param
        (
            [OutputType([Type])]

            [Parameter( Position = 0)]
            [Type[]]
            $Parameters = (New-Object Type[](0)),

            [Parameter( Position = 1 )]
            [Type]
            $ReturnType = [Void],

            [String]$Parpy='hello',
            [Integer] $puppy = 1,

            [Array[]] $stuff = Array[],
        )

        $Domain = [AppDomain]::CurrentDomain
        $DynAssembly = New-Object System.Reflection.AssemblyName('ReflectedDelegate')
        $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
        $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('InMemoryModule', $false)
        $TypeBuilder = $ModuleBuilder.DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
        $ConstructorBuilder = $TypeBuilder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $Parameters)
        $ConstructorBuilder.SetImplementationFlags('Runtime, Managed')
        $MethodBuilder = $TypeBuilder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $ReturnType, $Parameters)
        $MethodBuilder.SetImplementationFlags('Runtime, Managed')

        Write-Output $TypeBuilder.CreateType()
    }"""
  end

  describe "::initialize" do
    it 'should handle a function without params' do
      function = Rex::Powershell::Function.new(function_name, example_function_without_params)
<<<<<<< HEAD:spec/lib/rex/powershell/function_spec.rb
      expect(function.name).to eq function_name
      expect(function.code).to eq example_function_without_params
      expect(function.to_s.include?("function #{function_name} #{example_function_without_params}")).to be_truthy
      expect(function.params).to be_kind_of Array
      expect(function.params.empty?).to be_truthy
=======
      function.name.should eq function_name
      function.code.should eq example_function_without_params
      function.to_s.include?("function #{function_name} #{example_function_without_params}").should be_truthy
      function.params.should be_kind_of Array
      function.params.empty?.should be_truthy
>>>>>>> origin/chore/MSP-12110/celluloid-supervision-tree:spec/lib/rex/powershell/function_spec.rb
    end

    it 'should handle a function with params' do
      function = Rex::Powershell::Function.new(function_name, example_function_with_params)
<<<<<<< HEAD:spec/lib/rex/powershell/function_spec.rb
      expect(function.name).to eq function_name
      expect(function.code).to eq example_function_with_params
      expect(function.to_s.include?("function #{function_name} #{example_function_with_params}")).to be_truthy
      expect(function.params).to be_kind_of Array
      expect(function.params.length).to be == 5
      expect(function.params[0].klass).to eq 'Type[]'
      expect(function.params[0].name).to eq 'Parameters'
      expect(function.params[1].klass).to eq 'Type'
      expect(function.params[1].name).to eq 'ReturnType'
=======
      function.name.should eq function_name
      function.code.should eq example_function_with_params
      function.to_s.include?("function #{function_name} #{example_function_with_params}").should be_truthy
      function.params.should be_kind_of Array
      function.params.length.should be == 5
      function.params[0].klass.should eq 'Type[]'
      function.params[0].name.should eq 'Parameters'
      function.params[1].klass.should eq 'Type'
      function.params[1].name.should eq 'ReturnType'
>>>>>>> origin/chore/MSP-12110/celluloid-supervision-tree:spec/lib/rex/powershell/function_spec.rb
    end
  end

end

