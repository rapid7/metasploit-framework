
## Vulnerable Application

  Enumerate PCI hardware information from the registry. Please note this script will run through registry subkeys such as: 'PCI', 'ACPI', 'ACPI_HAL', 'FDC', 'HID', 'HTREE', 'IDE', 'ISAPNP', 'LEGACY'', LPTENUM', 'PCIIDE', 'SCSI', 'STORAGE', 'SW', and 'USB'; it will take time to finish. It is recommended to run this module as a background job.

## Verification Steps

  1. Start `msfconsole`
  2. Get meterpreter session
  3. Do: `use post/windows/gather/enum_devices`
  4. Do: `set SESSION <session id>`
  5. Do: `run`

## Options

  ```
  SESSION
  ```
  The session to run the module on.


## Scenarios

  ```
  [*] Meterpreter session 1 opened (192.168.1.3:4444 -> 192.168.1.10:49160) at 2019-12-11 15:45:16 -0700

  msf > use post/windows/gather/enum_devices
  msf post(windows/gather/enum_devices) > set SESSION 1
    SESSION => 1
  msf post(windows/gather/enum_devices) > run

    [*] Enumerating hardware on TEST-PC
    [+] Results saved in: /root/.msf4/loot/20191211161351_default_192.168.1.10_host.hardware_245183.txt
    [*] Post module execution completed
  ```

## Example of looted output

  ```
    [*] exec: cat /root/.msf4/loot/20191211161351_default_192.168.1.10_host.hardware_245183.txt

    Device Information
    ==================

    Device Description                                     Driver Version   Class         Manufacturer                          Extra
    ------------------                                     --------------   -----         ------------                          -----
    ACPI Fixed Feature Button                              6.1.7601.17514   System        (Standard system devices)
    ACPI x86-based PC                                      6.1.7600.16385   Computer      (Standard computers)
    AMD K8 Processor                                       6.1.7600.16385   Processor     Advanced Micro Devices                Common KVM processor
    Beep                                                                    LegacyDriver
    CD-ROM Drive                                           6.1.7601.17514   CDROM         (Standard CD-ROM drives)              QEMU QEMU DVD-ROM ATA Device
    CD/DVD File System Reader                                               LegacyDriver
    CNG                                                                     LegacyDriver
    Composite Bus Enumerator                               6.1.7601.17514   System        Microsoft
    Disk drive                                             6.1.7600.16385   DiskDrive     (Standard disk drives)                Red Hat VirtIO SCSI Disk Device
    ...snip...
  ```
