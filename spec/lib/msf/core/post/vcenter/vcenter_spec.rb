require 'spec_helper'

RSpec.describe Msf::Post::Vcenter::Vcenter do
  subject do
    mod = Msf::Module.new
    mod.extend(Msf::Post::Vcenter::Vcenter)
    mod
  end

  context 'gets builds correctly' do
    it 'from failing' do
      allow(subject).to receive(:command_exists?).and_return(false)
      allow(subject).to receive(:file_exist?).and_return(false)
      expect(subject.get_vcenter_build).to be_nil
    end
    it 'from vpxd' do
      allow(subject).to receive(:command_exists?).and_return(true)
      allow_any_instance_of(Msf::Post::Common).to receive(:cmd_exec).and_return("VMware VirtualCenter 6.7.0 build-18831049\n")
      expect(subject.get_vcenter_build).to eq('VMware VirtualCenter 6.7.0 build-18831049')
    end
    it 'from xml' do
      allow(subject).to receive(:command_exists?).and_return(false)
      allow(subject).to receive(:file_exist?).and_return(true)
      allow(subject).to receive(:read_file).and_return('<?xml version="1.0"?>
            <update xmlns:vadk="http://www.vmware.com/schema/vadk" xmlns:ovf="http://schemas.dmtf.org/ovf/envelope/1" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:vmw="http://www.vmware.com/schema/ovf">
              <product>VMware vCenter Server Appliance</product>
              <version>6.7.0.0</version>
              <fullVersion>6.7.0.0 Build 18796291</fullVersion>
              <vendor>VMware Inc.</vendor>
              <vendorUUID>706ee0c0-b51c-11de-8a39-0800200c9a66</vendorUUID>
              <productRID>8d167796-34d5-4899-be0a-6daade4005a3</productRID>
              <vendorURL>http://www.vmware.com</vendorURL>
              <productURL/>
              <supportURL/>
              <releaseDate>20211019055838.000000+000</releaseDate>
              <description>VMware vCenter Server Appliance
            Version 6.7.0</description>
              <EULAList showPolicy="" introducedVersion=""/>
              <UpdateInfoList>
                <UpdateInfo introduced-version="" category="feature" severity="important" affected-versions="" description="" reference-type="vendor" reference-id="" reference-url=""/>
              </UpdateInfoList>
              <preInstallScript>#!/bin/sh
            #Sample pre install update script
            #This script will be executed with the following arguments:
            #  $1 - version of VM before update
            #  $2 - version of VM trying to be installed

            if [ "$1" \&lt; "6.7" ]; then
               echo "Cannot update from version before 6.7: $1"
               exit 1
            fi

            echo "Installing update from version $1 to version $2"

            #preserve configs that could be overwritten
            # preserve pam config changes we set during NIS/AD setup process
            PAM_BACKUP_PATH="/var/vmware/vpxd/pam"
            mkdir -p "$PAM_BACKUP_PATH"
            cp -f /etc/pam.d/common-account "$PAM_BACKUP_PATH"
            cp -f /etc/pam.d/common-auth "$PAM_BACKUP_PATH"
            cp -f /etc/pam.d/sshd "$PAM_BACKUP_PATH"
            cp -f /etc/pam.d/login "$PAM_BACKUP_PATH"

            # preserve the syslog configuration
            SYSLOG_BACKUP_PATH="/var/vmware/vpxd/syslog"
            mkdir -p "$SYSLOG_BACKUP_PATH"
            cp -f /etc/sysconfig/syslog-collector "$SYSLOG_BACKUP_PATH"

            #exit with value of 0 to allow update to continue
            exit 0
                    </preInstallScript>
              <postInstallScript>#!/bin/sh
            #Sample post install update script
            #This script will be executed with the following arguments:
            #  $1 - version of VM before update
            #  $2 - version of VM trying to be installed
            #  $3 - status of update process
            #
            #The Status in $3 will indicate to success of failure of the update:
            #  0 - all update steps are successful
            #  1 - pre install script failed, package test and installation skipped
            #  2 - pre install success, package test failed, installation skipped
            #  4 - pre install and package test success, package installation failed
            #
            #A Status of 2 is likely caused by a package dependency conflict.  A Status of 4
            #is likely caused by a failed package install script.

            # Hide eula in vCenter service if eula has been accepted
            (
               . /usr/sbin/vpxd_commonutils
               if [ -e "$EULA_ACCEPTED" ]; then
                  hide_eula_from_web_ui
               fi
            )

            /usr/lib/vmware-vpx/rpmpatches.sh || exit 1

            #write back preserved configuration
            #restore pam config files. needed for PR 781377
            PAM_BACKUP_PATH="/var/vmware/vpxd/pam"
            mv -f "$PAM_BACKUP_PATH/common-account" /etc/pam.d
            mv -f "$PAM_BACKUP_PATH/common-auth" /etc/pam.d
            mv -f "$PAM_BACKUP_PATH/sshd" /etc/pam.d
            mv -f "$PAM_BACKUP_PATH/login" /etc/pam.d

            # restore the syslog configuration
            SYSLOG_BACKUP_PATH="/var/vmware/vpxd/syslog"
            mv -f "$SYSLOG_BACKUP_PATH/syslog-collector" /etc/sysconfig

            if [ $3 -eq 0 ]; then
              # Fix SSH banner with the new version
              echo -n "VMware vCenter Server Appliance " &gt; /etc/ssh/banner
              echo "@@FULLVERSION@@" &gt;&gt; /etc/ssh/banner

              echo "Finished installing version $2"
            else
              echo "Failed with status of $3 while installing version $2"
              echo "VM version is still $1"
            fi

            #Exit with a value of 0 to allow the VM version to be changed and set the final
            #update status to success.

            # Make python3 as default python
            /bin/ln -s /bin/python3 /bin/python
            /bin/ln -s /bin/python3 /usr/bin/python

            #disable cloud-int service PR1982599
            systemctl disable cloud-init-local.service
            systemctl disable cloud-init.service
            systemctl disable cloud-config.service
            systemctl disable cloud-final.service

            exit 0
                    </postInstallScript>
              <Network protocols="IPv4,IPv6"/>
            </update>')
      expect(subject.get_vcenter_build).to eq('VMware vCenter Server Appliance 6.7.0.0 Build 18796291')
    end
  end

  context 'gets deployment type correctly' do
    it 'from failing' do
      allow(subject).to receive(:file_exist?).and_return(false)
      expect(subject.get_deployment_type).to be_nil
    end
    it 'from deployment file' do
      allow(subject).to receive(:file_exist?).and_return(true)
      allow(subject).to receive(:read_file).and_return("embedded\n")
      expect(subject.get_deployment_type).to eq('embedded')
    end
  end

  context 'gets fqdn' do
    it 'from failing' do
      allow(subject).to receive(:file_exist?).and_return(false)
      allow(subject).to receive(:command_exists?).and_return(false)
      expect(subject.get_fqdn).to be_nil
    end
    it 'from vami commands' do
      allow(subject).to receive(:command_exists?).and_return(true)
      allow(subject).to receive(:cmd_exec).with('/opt/vmware/share/vami/vami_hname').and_return("photon-machine\n")
      allow(subject).to receive(:cmd_exec).with('/opt/vmware/share/vami/vami_domain').and_return("homedomain\n")
      expect(subject.get_fqdn).to eq('photon-machine.homedomain')
    end
    it 'from file' do
      allow(subject).to receive(:command_exists?).and_return(false)
      allow(subject).to receive(:file_exist?).and_return(true)
      allow(subject).to receive(:read_file).and_return("photon-machine.homedomain\n")
      expect(subject.get_fqdn).to eq('photon-machine.homedomain')
    end
    it 'and returns nil for bogus content' do
      allow(subject).to receive(:command_exists?).and_return(false)
      allow(subject).to receive(:file_exist?).and_return(true)
      allow(subject).to receive(:read_file).and_return("This command was not found on the system\n")
      expect(subject.get_fqdn).to be_nil
    end
  end

  context 'gets ipv4' do
    it 'from ifconfig command with interface' do
      allow(subject).to receive(:cmd_exec).with('ifconfig | grep eth0 -A1 | grep "inet addr:"').and_return("          inet addr:10.10.1.100  Bcast:10.10.1.255  Mask:255.255.255.0\n")
      expect(subject.get_ipv4).to eq('10.10.1.100')
    end
    it 'from ifconfig command with non-existent interface' do
      allow(subject).to receive(:cmd_exec).with('ifconfig | grep eth0 -A1 | grep "inet addr:"').and_return('')
      expect(subject.get_ipv4).to be_nil
    end
  end

  context 'gets host os' do
    it 'from failing' do
      allow(subject).to receive(:file_exist?).and_return(false)
      expect(subject.get_os_version).to be_nil
    end
    it 'from file' do
      allow(subject).to receive(:file_exist?).and_return(true)
      allow(subject).to receive(:read_file).and_return("VMware Photon Linux 1.0
        PHOTON_BUILD_NUMBER=62c543d\n")
      expect(subject.get_os_version).to eq(['VMware Photon Linux 1.0', '62c543d'])
    end
  end

  context 'gets machine id' do
    it 'from failing' do
      allow(subject).to receive(:command_exists?).and_return(false)
      expect(subject.get_machine_id).to be_nil
    end
    it 'from localhost' do
      allow(subject).to receive(:command_exists?).and_return(true)
      allow(subject).to receive(:cmd_exec).and_return("000be691-000a-0a0a-0000-c63a6276ea0a\n")
      expect(subject.get_machine_id).to eq('000be691-000a-0a0a-0000-c63a6276ea0a')
    end
  end

  context 'gets domain name' do
    it 'from failing' do
      allow(subject).to receive(:command_exists?).and_return(false)
      expect(subject.get_domain_name).to be_nil
    end
    it 'from localhost' do
      allow(subject).to receive(:command_exists?).and_return(true)
      allow(subject).to receive(:cmd_exec).and_return("vsphere.local\n")
      expect(subject.get_domain_name).to eq('vsphere.local')
    end
  end

  context 'gets domain dc dn' do
    it 'from failing' do
      allow(subject).to receive(:command_exists?).and_return(false)
      expect(subject.get_domain_dc_dn).to be_nil
    end
    it 'from localhost' do
      allow(subject).to receive(:command_exists?).and_return(true)
      allow(subject).to receive(:cmd_exec).and_return("cn=photon-machine.domain,ou=Domain Controllers,dc=vsphere,dc=local\n")
      expect(subject.get_domain_dc_dn).to eq('cn=photon-machine.domain,ou=Domain Controllers,dc=vsphere,dc=local')
    end
  end

  context 'gets domain dc password' do
    it 'from failing' do
      allow(subject).to receive(:command_exists?).and_return(false)
      expect(subject.get_domain_dc_password).to be_nil
    end
    it 'from localhost' do
      allow(subject).to receive(:command_exists?).and_return(true)
      allow(subject).to receive(:cmd_exec).and_return("\"1AaaA4Qh{7,9a`WIZ8Nk\"\n")
      expect(subject.get_domain_dc_password).to eq('1AaaA4Qh{7,9a`WIZ8Nk')
    end
    it 'from localhost with double quote' do
      allow(subject).to receive(:command_exists?).and_return(true)
      allow(subject).to receive(:cmd_exec).and_return("\"1AaaA4Q\"h{7,9a`WIZ8Nk\"\n")
      expect(subject.get_domain_dc_password).to eq('1AaaA4Q"h{7,9a`WIZ8Nk')
    end
  end

  context 'gets ldf contents' do
    it 'from failing with old file delete' do
      allow(subject).to receive(:file_exist?).and_return(true)
      allow(subject).to receive(:rm_f).and_return(nil)
      allow(subject).to receive(:read_file).and_return(nil)
      allow(subject).to receive(:cmd_exec).and_return('')
      expect(subject.get_ldif_contents(nil, nil, nil, nil, nil)).to be_nil
    end
    it 'from localhost' do
      allow(subject).to receive(:file_exist?).and_return(true)
      allow(subject).to receive(:rm_f).and_return(nil)
      allow(subject).to receive(:read_file).and_return('a')
      allow(subject).to receive(:cmd_exec).and_return('')
      expect(subject.get_ldif_contents(nil, nil, nil, nil, nil)).to eq('a')
    end
    it 'from localhost with newlines' do
      allow(subject).to receive(:file_exist?).and_return(true)
      allow(subject).to receive(:rm_f).and_return(nil)
      allow(subject).to receive(:read_file).and_return("a\n\nb\n")
      allow(subject).to receive(:cmd_exec).and_return('')
      expect(subject.get_ldif_contents(nil, nil, nil, nil, nil)).to eq("a\nb\n")
    end
  end

  context 'gets vecs stores' do
    it 'from failing to find command' do
      allow(subject).to receive(:command_exists?).and_return(false)
      expect(subject.get_vecs_stores).to be_nil
    end
    it 'from failing to find output' do
      allow(subject).to receive(:command_exists?).and_return(true)
      allow(subject).to receive(:cmd_exec).and_return(nil)
      expect(subject.get_vecs_stores).to be_nil
    end
    it 'from localhost' do
      allow(subject).to receive(:command_exists?).and_return(true)
      allow(subject).to receive(:cmd_exec).and_return("MACHINE_SSL_CERT\nTRUSTED_ROOTS\nTRUSTED_ROOT_CRLS\nmachine\nvsphere-webclient\nvpxd\nvpxd-extension\nAPPLMGMT_PASSWORD\ndata-encipherment\nSMS\n")
      expect(subject.get_vecs_stores).to eq(['MACHINE_SSL_CERT', 'TRUSTED_ROOTS', 'TRUSTED_ROOT_CRLS', 'machine', 'vsphere-webclient', 'vpxd', 'vpxd-extension', 'APPLMGMT_PASSWORD', 'data-encipherment', 'SMS'])
    end
  end
  # XXX need to add a run with multiple entries to ensure its processed correctly
  context 'gets vecs entries' do
    it 'from failing to find command' do
      allow(subject).to receive(:command_exists?).and_return(false)
      expect(subject.get_vecs_entries('SMS')).to be_nil
    end
    it 'processes one entry' do
      allow(subject).to receive(:command_exists?).and_return(true)
      allow(subject).to receive(:cmd_exec).and_return("Number of entries in store :\t1\nAlias :\tsms_self_signed\nEntry type :\tPrivate Key\nCertificate :\t-----BEGIN CERTIFICATE-----\nMIIC3DCCAcSgAwIBAgIGAYAyUuT9MA0GCSqGSIb3DQEBCwUAMC8xDzANBgNVBAoT\nBlZNd2FyZTEcMBoGA1UEAxMTU01TLTIyMDQxNjEyMjIxNTAzNzAeFw0yMTA0MTYx\nMjIyMTVaFw0zMjA0MTYxMjIyMTVaMC8xDzANBgNVBAoTBlZNd2FyZTEcMBoGA1UE\nAxMTU01TLTIyMDQxNjEyMjIxNTAzNzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC\nAQoCggEBALEONOdoulT/2Ku7urN+VkkloBarUZUB4MGO8YqHBVET4KwJE/3y/qgB\nq+9DHySeFVoTs79pvJkrVRZDSE4dtFaJQ7XdfFpiGU5P3fOmzyDrudqhpe6vjTX9\nb0sacrjm86iY7tCbJt3qDkWvqi4PSZ0fYmSjrPVpfs+h2/Ukx5oTeD5so04iODbi\nlHNsp4hg29C87oXD2AEx94nJsxVqQJll77z0MIDskeCwhVdVwQ0KNUjH2LD99KfO\nsR3bLVGGso3TS6GeU8dOINLY3n3yWtAVoRJ14A/rBLPrlvGvxRyECeCXeO7Vj8Aq\nmjsU+5pcVLcn5PAaJaweZYGkETygr5MCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEA\nf/eRGKHnBPd9/kLSXDCqF/OXTze1aYEfiIjhuOO1jKLufwP6H0mRFs8pPoMwc+49\n3u93xfpT0c7spGsUg9tc5XOsHi6y+TvsNGYiql5+IrTkx53I0aQwdfjDyebo3JtE\nOvmBeJ1zlXQMoVJeNS7szMg8A/fFkRXqxmJqZpsX/BZslRaXXfH8K5gx2w5Tk0fz\nZ5RMrdzjXwVYxnsF/zaNwg/8XZd3Ylp+EgERzfcJB9FJT1oJuktWlarIQ8mPJtu4\nC5fnrdvT3vfFZKwDZm1/I3nmhdxr4QQyQ/30gPqwKa2RUkFANiaY76+hiIr5ttLO\nJL28Kt/kjMpKfOKYxzPKbQ==\n-----END CERTIFICATE-----")
      expect(subject.get_vecs_entries('SMS')).to eq([
        {
          'Alias' => 'sms_self_signed',
          'Entry type' => 'Private Key',
          'Certificate' =>
                  "-----BEGIN CERTIFICATE-----\nMIIC3DCCAcSgAwIBAgIGAYAyUuT9MA0GCSqGSIb3DQEBCwUAMC8xDzANBgNVBAoT\nBlZNd2FyZTEcMBoGA1UEAxMTU01TLTIyMDQxNjEyMjIxNTAzNzAeFw0yMTA0MTYx\nMjIyMTVaFw0zMjA0MTYxMjIyMTVaMC8xDzANBgNVBAoTBlZNd2FyZTEcMBoGA1UE\nAxMTU01TLTIyMDQxNjEyMjIxNTAzNzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC\nAQoCggEBALEONOdoulT/2Ku7urN+VkkloBarUZUB4MGO8YqHBVET4KwJE/3y/qgB\nq+9DHySeFVoTs79pvJkrVRZDSE4dtFaJQ7XdfFpiGU5P3fOmzyDrudqhpe6vjTX9\nb0sacrjm86iY7tCbJt3qDkWvqi4PSZ0fYmSjrPVpfs+h2/Ukx5oTeD5so04iODbi\nlHNsp4hg29C87oXD2AEx94nJsxVqQJll77z0MIDskeCwhVdVwQ0KNUjH2LD99KfO\nsR3bLVGGso3TS6GeU8dOINLY3n3yWtAVoRJ14A/rBLPrlvGvxRyECeCXeO7Vj8Aq\nmjsU+5pcVLcn5PAaJaweZYGkETygr5MCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEA\nf/eRGKHnBPd9/kLSXDCqF/OXTze1aYEfiIjhuOO1jKLufwP6H0mRFs8pPoMwc+49\n3u93xfpT0c7spGsUg9tc5XOsHi6y+TvsNGYiql5+IrTkx53I0aQwdfjDyebo3JtE\nOvmBeJ1zlXQMoVJeNS7szMg8A/fFkRXqxmJqZpsX/BZslRaXXfH8K5gx2w5Tk0fz\nZ5RMrdzjXwVYxnsF/zaNwg/8XZd3Ylp+EgERzfcJB9FJT1oJuktWlarIQ8mPJtu4\nC5fnrdvT3vfFZKwDZm1/I3nmhdxr4QQyQ/30gPqwKa2RUkFANiaY76+hiIr5ttLO\nJL28Kt/kjMpKfOKYxzPKbQ==\n-----END CERTIFICATE-----"
        }
      ])
    end
  end

  context 'gets vecs private key' do
    it 'from failing to find command' do
      allow(subject).to receive(:command_exists?).and_return(false)
      expect(subject.get_vecs_private_key('SMS', 'test')).to be_nil
    end
    it 'from failing to get a valid entry' do
      allow(subject).to receive(:command_exists?).and_return(true)
      allow(subject).to receive(:cmd_exec).and_return('this is not valid')
      expect(subject.get_vecs_private_key('SMS', 'test')).to be_nil
    end
    it 'processes a valid entry' do
      key = "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCxDjTnaLpU/9ir\nu7qzflZJJaAWq1GVAeDBjvGKhwVRE+CsCRP98v6oAavvQx8knhVaE7O/abyZK1UW\nQ0hOHbRWiUO13XxaYhlOT93zps8g67naoaXur401/W9LGnK45vOomO7Qmybd6g5F\nr6ouD0mdH2Jko6z1aX7Podv1JMeaE3g+bKNOIjg24pRzbKeIYNvQvO6Fw9gBMfeJ\nybMVakCZZe+89DCA7JHgsIVXVcENCjVIx9iw/fSnzrEd2y1RhrKN00uhnlPHTiDS\n2N598lrQFaESdeAP6wSz65bxr8UchAngl3ju1Y/AKpo7FPuaXFS3J+TwGiWsHmWB\npBE8oK+TAgMBAAECggEALXcldKr69irAu9C4L7FofN4RjuCtUWMrEOkg816aqeg9\n0E+Ad7y3UfMj8Iu+6otBlmDqzmNbj8WF0vKyFYUhMvuKjJ/0d80rDGYL665RD/YY\nQqEx1+nyjAOpWZLQFNURiqDC6oR85Y1d3t0uCSfZ0mQlwwwYtOhDLRQ2RGwOaWza\n8cV7lEePaQHqnxtjJy5XJNVUJTRRVzIM3HvseOe2nmDIUY23YvCP3wrnY6M2rAVQ\ny/JDxnB6qK+OtAlU/qJFAJkLYgBFgvrocUTeXKjEFIEOzsW8uXJQi0FEQURqdKrI\n797yxH5GXU1zzvawFcPxYe+Nm74c0S2ENtfpNpWE0QKBgQDh+FUOLS2hLbyZGtjJ\nHCIS/fxk/8PvEvpXNPkGwDg6mpWtJgV+l5NtlgNcLIMHBbxFogxO0SpIwABdstZz\n8Rl749u5kLd1/YIgCenSwP77mGdWG8BPbcqyI4FU4AIa8R8Uk985zM3EKa478f+0\nYBZsijAHZhWWrqU21WzEi6Vm2wKBgQDIlcPlmlvl9hkiKo/JwarcEEbbqMRRG80c\ntdrOD17IrNDMEa0aOWyR9bjCyIum+tDSUaL5xu+4e7Ewc8PE5H3kKC3Q913MxxFN\nQIoqo/iMRVbGPjY4GP2vcF3aSSk0Sq5z3g4rJy/GLckYWa/YT6z65zz26HEh01jC\niqBaBksrqQKBgQDMlQ48hX6YPFZRr1Kx0TywQS7vKfh0TJRFu/nxuLmvpSD54EB9\nOjIJtxVXsBz4kKLB0FKgURKdRueN7UnnMlNGLSdTO8g9lMToyNDfNEgl9PcpqHpV\n7yriWO7QrvZ4+fCPqskhBWENxkaukwxUe+IRZpLRQAUvpPKDUHrm/x9CnQKBgCny\n+FcqYxHC2BrHH+8n652+YbNKplP4JntcpPf3SvFZAwnKoJMdc1FLPGqwGlS/m7CA\nlj76lePVKodhjo284381z+8l7J4I+9tWJg8o37AmSDGJjTlKMLPiIh6mslFXVQiy\nZfAsb9dYd/f5ucbZUuneNmfE0PQsCSIWb9aj/lCRAoGBAMmj4ycItiREuNX3o7uf\ngUt7j+7sEUp2zOQ9DNtOHhJ1wAFP6OtHG9hOIpIbxPS5zom3HPh9fdOMxqdsuFuI\nkfnz7POjCwTTc0u2kNQ2Ri901H6UKiOT3b1+O1VfbJbu1LtUEqpAoeKOgprvqagq\n0kSTpzJ0pcThb1nmHfFfzYPE\n-----END PRIVATE KEY-----"
      allow(subject).to receive(:command_exists?).and_return(true)
      allow(subject).to receive(:cmd_exec).and_return(key)
      expect(subject.get_vecs_private_key('SMS', 'test').to_s).to eq(OpenSSL::PKey::RSA.new(key).to_s)
    end
  end

  context 'gets vpx coustomization xml' do
    it 'from failing to find command' do
      allow(subject).to receive(:command_exists?).and_return(false)
      expect(subject.get_vpx_customization_spec('test', 'test', 'test')).to be_nil
    end
    it 'from failing to get a valid entry' do
      allow(subject).to receive(:command_exists?).and_return(true)
      allow(subject).to receive(:cmd_exec).and_return('this is not valid')
      expect(subject.get_vpx_customization_spec('test', 'test', 'test')).to eq({})
    end
    it 'with a valid entry' do
      allow(subject).to receive(:command_exists?).and_return(true)
      allow(subject).to receive(:cmd_exec).and_return('<xml></xml>')
      # we need to convert the XML:Doc back to a string so it can be tested correctly
      expect(subject.get_vpx_customization_spec('test', 'test', 'test').map { |k, v| [k.to_s, v.to_s] }.to_h).to eq({ '<xml></xml>' => "<?xml version=\"1.0\"?>\n<xml/>\n" })
    end
  end
  # XXX need to add a real user test
  context 'gets vpx users' do
    it 'from failing to find command' do
      allow(subject).to receive(:command_exists?).and_return(false)
      expect(subject.get_vpx_users('test', 'test', 'test', 'test')).to be_nil
    end
    it 'from failing to get a valid entry' do
      allow(subject).to receive(:command_exists?).and_return(true)
      allow(subject).to receive(:cmd_exec).and_return('this is not valid')
      expect(subject.get_vpx_users('test', 'test', 'test', 'test')).to eq([])
    end
    it 'with a valid entry' do
      allow(subject).to receive(:command_exists?).and_return(true)
      allow(subject).to receive(:cmd_exec).and_return('localhost|127.0.0.1|root|*')
      # we need to convert the XML:Doc back to a string so it can be tested correctly
      expect(subject.get_vpx_users('test', 'test', 'test', 'test')).to eq([
        {
          'fqdn' => 'localhost',
          'ip' => '127.0.0.1',
          'user' => 'root',
          'password' => ''
        }
      ])
    end
    # XXX need to add a valid test where we actually decrypt something
  end

  context 'gets vcdb properties' do
    it 'from failing to find command' do
      allow(subject).to receive(:file_exist?).and_return(false)
      expect(subject.process_vcdb_properties_file).to be_nil
    end
    it 'from failing to get a valid entry' do
      allow(subject).to receive(:file_exist?).and_return(true)
      allow(subject).to receive(:read_file).and_return('this is not valid')
      expect(subject.process_vcdb_properties_file).to eq({})
    end
    it 'and processes them correctly' do
      allow(subject).to receive(:file_exist?).and_return(true)
      allow(subject).to receive(:read_file).and_return("driver = org.postgresql.Driver\ndbtype = PostgreSQL\nurl = jdbc:postgresql://localhost:5432/VCDB\nusername = vc\npassword = MB&|<)haN6Q>{K3O\npassword.encrypted = false")
      expect(subject.process_vcdb_properties_file).to eq({
        'driver' => 'org.postgresql.Driver',
        'dbtype' => 'PostgreSQL',
        'url' => 'jdbc:postgresql://localhost:5432/VCDB',
        'username' => 'vc',
        'password' => 'MB&|<)haN6Q>{K3O',
        'password.encrypted' => 'false',
        'name' => 'VCDB',
        'host' => 'localhost',
        'port' => '5432',
        'db_engine' => 'postgresql'
      })
    end
  end

  context 'validates uuids' do
    it 'when not uuids' do
      expect(subject.is_uuid?('foobar')).to be(false)
    end
    it 'for uuids' do
      expect(subject.is_uuid?('123e4567-e89b-12d3-a456-426614174000')).to be(true)
    end
  end

  context 'validates DNs' do
    it 'when not a dn' do
      expect(subject.is_dn?('foobar')).to be(false)
    end
    it 'for uuids' do
      expect(subject.is_dn?('cn=photon-machine.domain,ou=Domain Controllers,dc=vsphere,dc=local')).to be(true)
    end
  end

  context 'validates x509 certificate' do
    it 'when not a certificate' do
      expect(subject.validate_x509_cert('foobar')).to be_nil
    end
    it 'for certificate' do
      cert = "-----BEGIN CERTIFICATE-----\nMIIEKzCCAxOgAwIBAgIJAP2y9h6OyvQ4MA0GCSqGSIb3DQEBCwUAMIGgMQswCQYD\nVQQDDAJDQTEXMBUGCgmSJomT8ixkARkWB3ZzcGhlcmUxFTATBgoJkiaJk/IsZAEZ\nFgVsb2NhbDELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExIjAgBgNV\nBAoMGXBob3Rvbi1tYWNoaW5lLnJhZ2Vkb21haW4xGzAZBgNVBAsMElZNd2FyZSBF\nbmdpbmVlcmluZzAeFw0yMjA0MTMxMjE2MjBaFw0zMjA0MTAxMjE2MjBaMIGgMQsw\nCQYDVQQDDAJDQTEXMBUGCgmSJomT8ixkARkWB3ZzcGhlcmUxFTATBgoJkiaJk/Is\nZAEZFgVsb2NhbDELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExIjAg\nBgNVBAoMGXBob3Rvbi1tYWNoaW5lLnJhZ2Vkb21haW4xGzAZBgNVBAsMElZNd2Fy\nZSBFbmdpbmVlcmluZzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKWe\nLiqdCHm7eOMLFZciwHd0XrIxNUlYBnAn5OzvxhuTcp0YIatF+FMugrCsrh8Tgweg\nEPAso+VgTlTPBqGELIQgIJzcBwYU+/V7LhlEnoe96YzATg2P+yzhfJk12l8b6pUS\ngY6toPrdxYSdhVxJdejH0h7zJj4JaC2hqKdgccLXcoEBJKr5RRhcwunmBnGlKSJn\nx2/c86O+tY4YD5/cJtCJZ4bOBdBCkDAxkFplTxy0ALzwKaq9zAydC/0Opgk7u25J\nphrWgRXAFbWdVHuR3HNpcndATIcHUzbnIGXzyOTi3Q+MhwglsTuRDL7mTJxgQvIA\n5Z7zBIjgqcrr+CUVLbcCAwEAAaNmMGQwHQYDVR0OBBYEFCIsHxyxZY6GVVayBTfU\nOZPflwtYMB8GA1UdEQQYMBaBDmVtYWlsQGFjbWUuY29thwR/AAABMA4GA1UdDwEB\n/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/AgEAMA0GCSqGSIb3DQEBCwUAA4IBAQA7\n+/cRuk2wQ6a7ORBaxAKhkKJ8oHVooEgGZaR1WADC63JePK06pgWA7dqo6tIs33dW\n4Mqbb0RVgX1CbrMrUatHuybIx3c6zOLAU8gpsW7V0NqPv9T/dLnZWGMFP8gnSHOx\ne818wwt3R6aKnmXHI0l3KYyPm/poVsTBxe3glTeR3D0kdUokQ3Up5Wctj8dGLBO+\n8/kMXJWFc788go2nJYp6Av8w4QwfnXSWbMrar3dRXKRj77rtnhvUMSeUTQnrW4r3\nM5tQmXjJ1vh93zZaCOH1ZmSMpWZ6LtWdXKY99ENfq23F6VGlptNlLXG2Ypzpq7BD\nc+ql1nH7Bd5TVPz589io\n-----END CERTIFICATE-----"
      expect(subject.validate_x509_cert(cert).to_s.strip).to eq(cert)
    end
    it 'for certificate without header' do
      cert = "MIIEKzCCAxOgAwIBAgIJAP2y9h6OyvQ4MA0GCSqGSIb3DQEBCwUAMIGgMQswCQYD\nVQQDDAJDQTEXMBUGCgmSJomT8ixkARkWB3ZzcGhlcmUxFTATBgoJkiaJk/IsZAEZ\nFgVsb2NhbDELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExIjAgBgNV\nBAoMGXBob3Rvbi1tYWNoaW5lLnJhZ2Vkb21haW4xGzAZBgNVBAsMElZNd2FyZSBF\nbmdpbmVlcmluZzAeFw0yMjA0MTMxMjE2MjBaFw0zMjA0MTAxMjE2MjBaMIGgMQsw\nCQYDVQQDDAJDQTEXMBUGCgmSJomT8ixkARkWB3ZzcGhlcmUxFTATBgoJkiaJk/Is\nZAEZFgVsb2NhbDELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExIjAg\nBgNVBAoMGXBob3Rvbi1tYWNoaW5lLnJhZ2Vkb21haW4xGzAZBgNVBAsMElZNd2Fy\nZSBFbmdpbmVlcmluZzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKWe\nLiqdCHm7eOMLFZciwHd0XrIxNUlYBnAn5OzvxhuTcp0YIatF+FMugrCsrh8Tgweg\nEPAso+VgTlTPBqGELIQgIJzcBwYU+/V7LhlEnoe96YzATg2P+yzhfJk12l8b6pUS\ngY6toPrdxYSdhVxJdejH0h7zJj4JaC2hqKdgccLXcoEBJKr5RRhcwunmBnGlKSJn\nx2/c86O+tY4YD5/cJtCJZ4bOBdBCkDAxkFplTxy0ALzwKaq9zAydC/0Opgk7u25J\nphrWgRXAFbWdVHuR3HNpcndATIcHUzbnIGXzyOTi3Q+MhwglsTuRDL7mTJxgQvIA\n5Z7zBIjgqcrr+CUVLbcCAwEAAaNmMGQwHQYDVR0OBBYEFCIsHxyxZY6GVVayBTfU\nOZPflwtYMB8GA1UdEQQYMBaBDmVtYWlsQGFjbWUuY29thwR/AAABMA4GA1UdDwEB\n/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/AgEAMA0GCSqGSIb3DQEBCwUAA4IBAQA7\n+/cRuk2wQ6a7ORBaxAKhkKJ8oHVooEgGZaR1WADC63JePK06pgWA7dqo6tIs33dW\n4Mqbb0RVgX1CbrMrUatHuybIx3c6zOLAU8gpsW7V0NqPv9T/dLnZWGMFP8gnSHOx\ne818wwt3R6aKnmXHI0l3KYyPm/poVsTBxe3glTeR3D0kdUokQ3Up5Wctj8dGLBO+\n8/kMXJWFc788go2nJYp6Av8w4QwfnXSWbMrar3dRXKRj77rtnhvUMSeUTQnrW4r3\nM5tQmXjJ1vh93zZaCOH1ZmSMpWZ6LtWdXKY99ENfq23F6VGlptNlLXG2Ypzpq7BD\nc+ql1nH7Bd5TVPz589io\n"
      expect(subject.validate_x509_cert(cert).to_s.strip).to eq("-----BEGIN CERTIFICATE-----\n#{cert}-----END CERTIFICATE-----")
    end
  end

  context 'validates private key' do
    it 'when not a private key' do
      expect(subject.validate_pkey('foobar')).to be_nil
    end
    it 'for pkey' do
      key = "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQClni4qnQh5u3jj\nCxWXIsB3dF6yMTVJWAZwJ+Ts78Ybk3KdGCGrRfhTLoKwrK4fE4MHoBDwLKPlYE5U\nzwahhCyEICCc3AcGFPv1ey4ZRJ6HvemMwE4Nj/ss4XyZNdpfG+qVEoGOraD63cWE\nnYVcSXXox9Ie8yY+CWgtoainYHHC13KBASSq+UUYXMLp5gZxpSkiZ8dv3POjvrWO\nGA+f3CbQiWeGzgXQQpAwMZBaZU8ctAC88CmqvcwMnQv9DqYJO7tuSaYa1oEVwBW1\nnVR7kdxzaXJ3QEyHB1M25yBl88jk4t0PjIcIJbE7kQy+5kycYELyAOWe8wSI4KnK\n6/glFS23AgMBAAECggEBAIWN3mrMwVXxQRXODXYYNx7dP7PwjKj9jAuLkEclQBti\ntu1J1XTZctwZSJiSV8OFp4dRo/cZ+HzzQZeQbyd2f7N4ePQlVqCn8VrPH6iOtkx+\ncETpmsfDEOjrWN/wFo3V5ECccM+O4p8KkcpUgIOgVa4G3UHKEE+8pD8P+wImevaE\nG/9b7LG3WDX/3WEoXERT4SNwKfTEXV/dYVBSH1iikI04VrRFtt7ob7kwJLw1GVnz\nfH2Q5cPdJzJsOG5LYTaXALYW9RlkmI2gaTrqBaUGm3n+jTB5OXactonWcHPMYsW/\nelc2AZeoQh/Dmwlmkzh6u8D1jrToRDk0GdWn1MkHhhECgYEA2wPnp5i3HYH5vFHS\n5o7lJJmoQaJmXmo50BEPguNedITkkWQTvqQ7cofSFASUragUQa7osePa27DH2xKz\n8kSdeSLR3QTApjF9JZGPSZdYnpiCadqbwlQ8VHKYdn3LB45lILD09fioobhJ385b\nRirIxNVKgOnW557eXk+Nx6TGa+8CgYEAwZXkOA0SADp2SdkO3pXe0r8BExA3eEpZ\nLHlDPbtkUCSMcApwF3Sm+WDHi21pLMX3Dpy7MVxpQLQD/VRNjtomEEe4Y4y50I2x\n2MMdn3nOBbcV/ExgNfjPPh0lamzcb3bPHUof4KEnIRisPdNjk9qiR3CFjFf0hviR\nhFPKEB6rsrkCgYASar6lKkNjuNVOT7cjaiq8rCso8cYX9GjOJVEfmY0M0UwDKd47\nLsZM+DzjMAtsmvCxIUsyAk4aIUB9HJKDMd/oGtR4+HhWwVybtyTMdGygUYTN7/Mf\nIUQ9ebF2bVeQWBoK6LaApJtRlhSoPEsSmHBvlNwCASfwLDzYw2nRuvpwgwKBgCbS\nf5U6Ec0X7Fb8/71lwuzyvy1qiCVIi7+ehfygUwq7eaqSfU5G56GFZh8xDvGateQp\nTGUmyjjeoRoxyOgIGbAUIgdc1nrbn7n/zzYHQGjnAbK6QmUwg6dKQxGnyUFVS03t\nap0q1GUPxKMVfJfPNdIr36x4iyJyQQSPpSs8a2SJAoGBAI3DQi4FzwWQccxIDLLq\nsg1q5lKDntWF/A0wQulnGSjnfRp4XYvkvW3LbJePZwwi/rTLJ3O2OhCor18I7MWY\nrh8BwIdN35aI2rwes69i3uRb9itTzz5JpOvxKltlAXVTAM5l1NF55tKPUwoFWeq2\nQ+vckvj2Cs8NQnQg9suxYfKM\n-----END PRIVATE KEY-----"
      pkcs8_key = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEApZ4uKp0Iebt44wsVlyLAd3ResjE1SVgGcCfk7O/GG5NynRgh\nq0X4Uy6CsKyuHxODB6AQ8Cyj5WBOVM8GoYQshCAgnNwHBhT79XsuGUSeh73pjMBO\nDY/7LOF8mTXaXxvqlRKBjq2g+t3FhJ2FXEl16MfSHvMmPgloLaGop2BxwtdygQEk\nqvlFGFzC6eYGcaUpImfHb9zzo761jhgPn9wm0Ilnhs4F0EKQMDGQWmVPHLQAvPAp\nqr3MDJ0L/Q6mCTu7bkmmGtaBFcAVtZ1Ue5Hcc2lyd0BMhwdTNucgZfPI5OLdD4yH\nCCWxO5EMvuZMnGBC8gDlnvMEiOCpyuv4JRUttwIDAQABAoIBAQCFjd5qzMFV8UEV\nzg12GDce3T+z8Iyo/YwLi5BHJUAbYrbtSdV02XLcGUiYklfDhaeHUaP3Gfh880GX\nkG8ndn+zeHj0JVagp/Fazx+ojrZMfnBE6ZrHwxDo61jf8BaN1eRAnHDPjuKfCpHK\nVICDoFWuBt1ByhBPvKQ/D/sCJnr2hBv/W+yxt1g1/91hKFxEU+EjcCn0xF1f3WFQ\nUh9YopCNOFa0Rbbe6G+5MCS8NRlZ83x9kOXD3ScybDhuS2E2lwC2FvUZZJiNoGk6\n6gWlBpt5/o0weTl2nLaJ1nBzzGLFv3pXNgGXqEIfw5sJZpM4ervA9Y606EQ5NBnV\np9TJB4YRAoGBANsD56eYtx2B+bxR0uaO5SSZqEGiZl5qOdARD4LjXnSE5JFkE76k\nO3KH0hQElK2oFEGu6LHj2tuwx9sSs/JEnXki0d0EwKYxfSWRj0mXWJ6Ygmnam8JU\nPFRymHZ9yweOZSCw9PX4qKG4Sd/OW0YqyMTVSoDp1uee3l5PjcekxmvvAoGBAMGV\n5DgNEgA6dknZDt6V3tK/ARMQN3hKWSx5Qz27ZFAkjHAKcBd0pvlgx4ttaSzF9w6c\nuzFcaUC0A/1UTY7aJhBHuGOMudCNsdjDHZ95zgW3FfxMYDX4zz4dJWps3G92zx1K\nH+ChJyEYrD3TY5PaokdwhYxX9Ib4kYRTyhAeq7K5AoGAEmq+pSpDY7jVTk+3I2oq\nvKwrKPHGF/RoziVRH5mNDNFMAyneOy7GTPg84zALbJrwsSFLMgJOGiFAfRySgzHf\n6BrUePh4VsFcm7ckzHRsoFGEze/zHyFEPXmxdm1XkFgaCui2gKSbUZYUqDxLEphw\nb5TcAgEn8Cw82MNp0br6cIMCgYAm0n+VOhHNF+xW/P+9ZcLs8r8taoglSIu/noX8\noFMKu3mqkn1ORuehhWYfMQ7xmrXkKUxlJso43qEaMcjoCBmwFCIHXNZ625+5/882\nB0Bo5wGyukJlMIOnSkMRp8lBVUtN7WqdKtRlD8SjFXyXzzXSK9+seIsickEEj6Ur\nPGtkiQKBgQCNw0IuBc8FkHHMSAyy6rINauZSg57VhfwNMELpZxko530aeF2L5L1t\ny2yXj2cMIv60yydztjoQqK9fCOzFmK4fAcCHTd+WiNq8HrOvYt7kW/YrU88+SaTr\n8SpbZQF1UwDOZdTReebSj1MKBVnqtkPr3JL49grPDUJ0IPbLsWHyjA==\n-----END RSA PRIVATE KEY-----"
      expect(subject.validate_pkey(key).to_s.strip).to eq(pkcs8_key)
    end
    it 'for pkey without header' do
      key = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQClni4qnQh5u3jj\nCxWXIsB3dF6yMTVJWAZwJ+Ts78Ybk3KdGCGrRfhTLoKwrK4fE4MHoBDwLKPlYE5U\nzwahhCyEICCc3AcGFPv1ey4ZRJ6HvemMwE4Nj/ss4XyZNdpfG+qVEoGOraD63cWE\nnYVcSXXox9Ie8yY+CWgtoainYHHC13KBASSq+UUYXMLp5gZxpSkiZ8dv3POjvrWO\nGA+f3CbQiWeGzgXQQpAwMZBaZU8ctAC88CmqvcwMnQv9DqYJO7tuSaYa1oEVwBW1\nnVR7kdxzaXJ3QEyHB1M25yBl88jk4t0PjIcIJbE7kQy+5kycYELyAOWe8wSI4KnK\n6/glFS23AgMBAAECggEBAIWN3mrMwVXxQRXODXYYNx7dP7PwjKj9jAuLkEclQBti\ntu1J1XTZctwZSJiSV8OFp4dRo/cZ+HzzQZeQbyd2f7N4ePQlVqCn8VrPH6iOtkx+\ncETpmsfDEOjrWN/wFo3V5ECccM+O4p8KkcpUgIOgVa4G3UHKEE+8pD8P+wImevaE\nG/9b7LG3WDX/3WEoXERT4SNwKfTEXV/dYVBSH1iikI04VrRFtt7ob7kwJLw1GVnz\nfH2Q5cPdJzJsOG5LYTaXALYW9RlkmI2gaTrqBaUGm3n+jTB5OXactonWcHPMYsW/\nelc2AZeoQh/Dmwlmkzh6u8D1jrToRDk0GdWn1MkHhhECgYEA2wPnp5i3HYH5vFHS\n5o7lJJmoQaJmXmo50BEPguNedITkkWQTvqQ7cofSFASUragUQa7osePa27DH2xKz\n8kSdeSLR3QTApjF9JZGPSZdYnpiCadqbwlQ8VHKYdn3LB45lILD09fioobhJ385b\nRirIxNVKgOnW557eXk+Nx6TGa+8CgYEAwZXkOA0SADp2SdkO3pXe0r8BExA3eEpZ\nLHlDPbtkUCSMcApwF3Sm+WDHi21pLMX3Dpy7MVxpQLQD/VRNjtomEEe4Y4y50I2x\n2MMdn3nOBbcV/ExgNfjPPh0lamzcb3bPHUof4KEnIRisPdNjk9qiR3CFjFf0hviR\nhFPKEB6rsrkCgYASar6lKkNjuNVOT7cjaiq8rCso8cYX9GjOJVEfmY0M0UwDKd47\nLsZM+DzjMAtsmvCxIUsyAk4aIUB9HJKDMd/oGtR4+HhWwVybtyTMdGygUYTN7/Mf\nIUQ9ebF2bVeQWBoK6LaApJtRlhSoPEsSmHBvlNwCASfwLDzYw2nRuvpwgwKBgCbS\nf5U6Ec0X7Fb8/71lwuzyvy1qiCVIi7+ehfygUwq7eaqSfU5G56GFZh8xDvGateQp\nTGUmyjjeoRoxyOgIGbAUIgdc1nrbn7n/zzYHQGjnAbK6QmUwg6dKQxGnyUFVS03t\nap0q1GUPxKMVfJfPNdIr36x4iyJyQQSPpSs8a2SJAoGBAI3DQi4FzwWQccxIDLLq\nsg1q5lKDntWF/A0wQulnGSjnfRp4XYvkvW3LbJePZwwi/rTLJ3O2OhCor18I7MWY\nrh8BwIdN35aI2rwes69i3uRb9itTzz5JpOvxKltlAXVTAM5l1NF55tKPUwoFWeq2\nQ+vckvj2Cs8NQnQg9suxYfKM\n"
      pkcs8_key = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEApZ4uKp0Iebt44wsVlyLAd3ResjE1SVgGcCfk7O/GG5NynRgh\nq0X4Uy6CsKyuHxODB6AQ8Cyj5WBOVM8GoYQshCAgnNwHBhT79XsuGUSeh73pjMBO\nDY/7LOF8mTXaXxvqlRKBjq2g+t3FhJ2FXEl16MfSHvMmPgloLaGop2BxwtdygQEk\nqvlFGFzC6eYGcaUpImfHb9zzo761jhgPn9wm0Ilnhs4F0EKQMDGQWmVPHLQAvPAp\nqr3MDJ0L/Q6mCTu7bkmmGtaBFcAVtZ1Ue5Hcc2lyd0BMhwdTNucgZfPI5OLdD4yH\nCCWxO5EMvuZMnGBC8gDlnvMEiOCpyuv4JRUttwIDAQABAoIBAQCFjd5qzMFV8UEV\nzg12GDce3T+z8Iyo/YwLi5BHJUAbYrbtSdV02XLcGUiYklfDhaeHUaP3Gfh880GX\nkG8ndn+zeHj0JVagp/Fazx+ojrZMfnBE6ZrHwxDo61jf8BaN1eRAnHDPjuKfCpHK\nVICDoFWuBt1ByhBPvKQ/D/sCJnr2hBv/W+yxt1g1/91hKFxEU+EjcCn0xF1f3WFQ\nUh9YopCNOFa0Rbbe6G+5MCS8NRlZ83x9kOXD3ScybDhuS2E2lwC2FvUZZJiNoGk6\n6gWlBpt5/o0weTl2nLaJ1nBzzGLFv3pXNgGXqEIfw5sJZpM4ervA9Y606EQ5NBnV\np9TJB4YRAoGBANsD56eYtx2B+bxR0uaO5SSZqEGiZl5qOdARD4LjXnSE5JFkE76k\nO3KH0hQElK2oFEGu6LHj2tuwx9sSs/JEnXki0d0EwKYxfSWRj0mXWJ6Ygmnam8JU\nPFRymHZ9yweOZSCw9PX4qKG4Sd/OW0YqyMTVSoDp1uee3l5PjcekxmvvAoGBAMGV\n5DgNEgA6dknZDt6V3tK/ARMQN3hKWSx5Qz27ZFAkjHAKcBd0pvlgx4ttaSzF9w6c\nuzFcaUC0A/1UTY7aJhBHuGOMudCNsdjDHZ95zgW3FfxMYDX4zz4dJWps3G92zx1K\nH+ChJyEYrD3TY5PaokdwhYxX9Ib4kYRTyhAeq7K5AoGAEmq+pSpDY7jVTk+3I2oq\nvKwrKPHGF/RoziVRH5mNDNFMAyneOy7GTPg84zALbJrwsSFLMgJOGiFAfRySgzHf\n6BrUePh4VsFcm7ckzHRsoFGEze/zHyFEPXmxdm1XkFgaCui2gKSbUZYUqDxLEphw\nb5TcAgEn8Cw82MNp0br6cIMCgYAm0n+VOhHNF+xW/P+9ZcLs8r8taoglSIu/noX8\noFMKu3mqkn1ORuehhWYfMQ7xmrXkKUxlJso43qEaMcjoCBmwFCIHXNZ625+5/882\nB0Bo5wGyukJlMIOnSkMRp8lBVUtN7WqdKtRlD8SjFXyXzzXSK9+seIsickEEj6Ur\nPGtkiQKBgQCNw0IuBc8FkHHMSAyy6rINauZSg57VhfwNMELpZxko530aeF2L5L1t\ny2yXj2cMIv60yydztjoQqK9fCOzFmK4fAcCHTd+WiNq8HrOvYt7kW/YrU88+SaTr\n8SpbZQF1UwDOZdTReebSj1MKBVnqtkPr3JL49grPDUJ0IPbLsWHyjA==\n-----END RSA PRIVATE KEY-----"
      expect(subject.validate_pkey(key).to_s.strip).to eq(pkcs8_key)
    end
  end

  context 'service controller' do
    it 'fails when bin not found' do
      allow(subject).to receive(:command_exists?).and_return(false)
      expect(subject.get_platform_service_controller).to be_nil
    end
    it 'gives localhost when not a manager' do
      allow(subject).to receive(:command_exists?).and_return(true)
      expect(subject.get_platform_service_controller(false)).to eq('localhost')
    end
    it 'gives localhost when not a manager' do
      allow(subject).to receive(:command_exists?).and_return(true)
      allow(subject).to receive(:cmd_exec).and_return('https://photon-machine.domain:443/lookupservice/sdk')
      expect(subject.get_platform_service_controller(true)).to eq('photon-machine.domain')
    end
  end

  context 'idp key' do
    it 'fails when bin not found' do
      allow(subject).to receive(:command_exists?).and_return(false)
      expect(subject.get_idp_keys(nil, nil, nil, nil, nil)).to be_nil
    end
    it 'gives back nil on failed command' do
      allow(subject).to receive(:command_exists?).and_return(true)
      allow(subject).to receive(:cmd_exec).and_return('ldap_bind: Invalid credentials (49)')
      allow(subject).to receive(:file_exist?).and_return(false)
      expect(subject.get_idp_keys(nil, nil, nil, nil, nil)).to be_nil
    end
    key = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC1VLel1Lc\n I9QtXriWxvQizqJUUqp8AmQo58nqbsiMrK8/32Qif+YspNUuhcOflo8H0QA3BIu+Wk3AD6V4Tvokw\n 2NKCNE9xZGHEVGrL5aqlNNSOOP7BAyEFeICSrtVDdEJlvCvsWU6/lUWX7Z7Di/FFJT2g1K7g25f3f\n KhN73fMEOAXdbTpPrSja/xFNA9Qup9WrIUyMNxU66ewecAVNibtuoTB1NwYrsgUfr1J8S8AsBy5GD\n at0aZDTiaOjcLxNIISwb4Zq5QCXIC6zEUOXBTeZNrZvvaDbskeNOkW6gMkU6599jenxkoAB45E+Xk\n 8E1RH/lB0yLD4r4jaUVu7APwJAgMBAAECggEBAKWuf5KU9pzHkZKOu0BYkZ/eVEEq2Ndp/i8OQDsM\n nBexE3fJpZjOIPoJCU68ZBat9uTetfKXokR5+KqKS3xM5vtr0YRImaHo72+9FkuxUKdcyy4cI6Fl4\n 4ElJo1gE9prWtOsCJIO0+Y3VPxJkHvp3Qypx1KxogwweP0XuIxlVpdr8gWqDwm/AN4xn4CVMLiN8k\n Y6n4uqf2oTihF31l0G1CLh7hEwp/BwZH018T6DUojqOb8nBak09kwG7o/4ZNuGMzWX83p0httMyFC\n 8EnTfccZL6xUcAK8VsMwY7dfGXIAOsAZFKa9lrvGCWE7+W2rOXh++lBEKJUWPHzTfrXQ1KgECgYEA\n +RO5FI0c8gXFfpT/2NHJWZf1+VF//F/M2FYxMqxBt+CaaHzfjvtBIOeMdAk+jKkf3JF2CqQeT7xOG\n ZXhWbrsUlESB3VHtc1g1sP+IFhPnODFEb08bXlhALoP6/tPYD+muKITd43i2H6EwBFLN1Yz1i9Bo7\n GJ4Go/BhGZ6AnmNUECgYEAul70i+zvZpEa3+M0F4Tt2Um9wnCtecq5U3EawxOTN15lSoJCvZxY8cz\n Ior8mX/2jBjMHGbfJPMc3V8c+kx4Lwi1LnoDAog+IycKp9kds6uHQzpvtDSu7WZSPymfm1de4nBxo\n 4zb7x8PC/BgYOCvZekzBBOr1566S9xxcPpuaLMkCgYBmJ7et/R5VCRbyDqxMQeaCD3g71DhYyvXZ+\n Kfe75VYlA7gMe8C1nvkwfLyGGSGDktaDHLMdHlWHJYvmjA9vBN2w3dQhcJuhxhjnSjaHT4xymIpH2\n LsR28IfEdRctYgVJrNePPhAdl7D5DksXMW9Az4mJMkTwmMeCb3Fzr3VzAKwQKBgGWn05XbJ/33GgS\n S5mAJxr6lpVbApS7wb8Pexq0vKTajS3antIW+GRnTDIEQ6HqlW13PSYkyoRaAx2QerrgKRHmmwT90\n lR4QgRkkEBbggL1hbMa1cEil2OwUx5WstNFheDXWnTOKUy10Tw+4iMVizZ4S7ZmkG3tC0rDtDDeuI\n htZAoGAKpVaxG7krdRYL67DtyFWJud4xt4YEQ6N+L5md1QypN5il1Nrooy/M5Hoae5QaiJQYyxPQe\n pS9hBFNpENXvGXB2WA1FeRVubRA52yIh2g6B4Vi/tMN08UoEFMShq4VkIYq6P3KrT9mXPR3LY3pBr\n Uf4kYz5Dy/H1msZVHVSBSC80="
    it 'gives back key on command success' do
      pkcs8_key = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAtVS3pdS3CPULV64lsb0Is6iVFKqfAJkKOfJ6m7IjKyvP99kI\nn/mLKTVLoXDn5aPB9EANwSLvlpNwA+leE76JMNjSgjRPcWRhxFRqy+WqpTTUjjj+\nwQMhBXiAkq7VQ3RCZbwr7FlOv5VFl+2ew4vxRSU9oNSu4NuX93yoTe93zBDgF3W0\n6T60o2v8RTQPULqfVqyFMjDcVOunsHnAFTYm7bqEwdTcGK7IFH69SfEvALAcuRg2\nrdGmQ04mjo3C8TSCEsG+GauUAlyAusxFDlwU3mTa2b72g27JHjTpFuoDJFOuffY3\np8ZKAAeORPl5PBNUR/5QdMiw+K+I2lFbuwD8CQIDAQABAoIBAQClrn+SlPacx5GS\njrtAWJGf3lRBKtjXaf4vDkA7DJwXsRN3yaWYziD6CQlOvGQWrfbk3rXyl6JEefiq\nikt8TOb7a9GESJmh6O9vvRZLsVCnXMsuHCOhZeOBJSaNYBPaa1rTrAiSDtPmN1T8\nSZB76d0MqcdSsaIMMHj9F7iMZVaXa/IFqg8JvwDeMZ+AlTC4jfJGOp+Lqn9qE4oR\nd9ZdBtQi4e4RMKfwcGR9NfE+g1KI6jm/JwWpNPZMBu6P+GTbhjM1l/N6dIbbTMhQ\nvBJ033HGS+sVHACvFbDMGO3XxlyADrAGRSmvZa7xglhO/ltqzl4fvpQRCiVFjx80\n3610NSoBAoGBAPkTuRSNHPIFxX6U/9jRyVmX9flRf/xfzNhWMTKsQbfgmmh83477\nQSDnjHQJPoypH9yRdgqkHk+8ThmV4Vm67FJREgd1R7XNYNbD/iBYT5zgxRG9PG15\nYQC6D+v7T2A/priiE3eN4th+hMARSzdWM9YvQaOxieBqPwYRmegJ5jVBAoGBALpe\n9Ivs72aRGt/jNBeE7dlJvcJwrXnKuVNxGsMTkzdeZUqCQr2cWPHMyKK/Jl/9owYz\nBxm3yTzHN1fHPpMeC8ItS56AwKIPiMnCqfZHbOrh0M6b7Q0ru1mUj8pn5tXXuJwc\naOM2+8fDwvwYGDgr2XpMwQTq9eeukvccXD6bmizJAoGAZie3rf0eVQkW8g6sTEHm\ngg94O9Q4WMr12fin3u+VWJQO4DHvAtZ75MHy8hhkhg5LWgxyzHR5VhyWL5owPbwT\ndsN3UIXCbocYY50o2h0+McpiKR9i7EdvCHxHUXLWIFSazXjz4QHZew+Q5LFzFvQM\n+JiTJE8JjHgm9xc691cwCsECgYBlp9OV2yf99xoEkuZgCca+paVWwKUu8G/D3sat\nLyk2o0t2p7SFvhkZ0wyBEOh6pVtdz0mJMqEWgMdkHq64CkR5psE/dJUeEIEZJBAW\n4IC9YWzGtXBIpdjsFMeVrLTRYXg11p0zilMtdE8PuIjFYs2eEu2ZpBt7QtKw7Qw3\nriIbWQKBgCqVWsRu5K3UWC+uw7chVibneMbeGBEOjfi+ZndUMqTeYpdTa6KMvzOR\n6GnuUGoiUGMsT0HqUvYQRTaRDV7xlwdlgNRXkVbm0QOdsiIdoOgeFYv7TDdPFKBB\nTEoauFZCGKuj9yq0/Zlz0dy2N6Qa1H+JGM+Q8vx9ZrGVR1UgUgvN\n-----END RSA PRIVATE KEY-----\n"
      command_output = "dn: cn=TenantCredential-1,cn=vsphere.local,cn=Tenants,cn=IdentityManager,cn=Se\n rvices,dc=vsphere,dc=local\nvmwSTSPrivateKey:: #{key}"
      allow(subject).to receive(:command_exists?).and_return(true)
      allow(subject).to receive(:cmd_exec).and_return(command_output)
      expect(subject.get_idp_keys(nil, nil, nil, nil, nil).map { |item| item.to_s }).to eq([pkcs8_key])
    end
    it 'gives back key on legacy file read' do
      key = "-----BEGIN PRIVATE KEY-----\n#{key}\n-----END PRIVATE KEY-----".gsub("\n ", "\n")
      pkcs8_key = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAtVS3pdS3CPULV64lsb0Is6iVFKqfAJkKOfJ6m7IjKyvP99kI\nn/mLKTVLoXDn5aPB9EANwSLvlpNwA+leE76JMNjSgjRPcWRhxFRqy+WqpTTUjjj+\nwQMhBXiAkq7VQ3RCZbwr7FlOv5VFl+2ew4vxRSU9oNSu4NuX93yoTe93zBDgF3W0\n6T60o2v8RTQPULqfVqyFMjDcVOunsHnAFTYm7bqEwdTcGK7IFH69SfEvALAcuRg2\nrdGmQ04mjo3C8TSCEsG+GauUAlyAusxFDlwU3mTa2b72g27JHjTpFuoDJFOuffY3\np8ZKAAeORPl5PBNUR/5QdMiw+K+I2lFbuwD8CQIDAQABAoIBAQClrn+SlPacx5GS\njrtAWJGf3lRBKtjXaf4vDkA7DJwXsRN3yaWYziD6CQlOvGQWrfbk3rXyl6JEefiq\nikt8TOb7a9GESJmh6O9vvRZLsVCnXMsuHCOhZeOBJSaNYBPaa1rTrAiSDtPmN1T8\nSZB76d0MqcdSsaIMMHj9F7iMZVaXa/IFqg8JvwDeMZ+AlTC4jfJGOp+Lqn9qE4oR\nd9ZdBtQi4e4RMKfwcGR9NfE+g1KI6jm/JwWpNPZMBu6P+GTbhjM1l/N6dIbbTMhQ\nvBJ033HGS+sVHACvFbDMGO3XxlyADrAGRSmvZa7xglhO/ltqzl4fvpQRCiVFjx80\n3610NSoBAoGBAPkTuRSNHPIFxX6U/9jRyVmX9flRf/xfzNhWMTKsQbfgmmh83477\nQSDnjHQJPoypH9yRdgqkHk+8ThmV4Vm67FJREgd1R7XNYNbD/iBYT5zgxRG9PG15\nYQC6D+v7T2A/priiE3eN4th+hMARSzdWM9YvQaOxieBqPwYRmegJ5jVBAoGBALpe\n9Ivs72aRGt/jNBeE7dlJvcJwrXnKuVNxGsMTkzdeZUqCQr2cWPHMyKK/Jl/9owYz\nBxm3yTzHN1fHPpMeC8ItS56AwKIPiMnCqfZHbOrh0M6b7Q0ru1mUj8pn5tXXuJwc\naOM2+8fDwvwYGDgr2XpMwQTq9eeukvccXD6bmizJAoGAZie3rf0eVQkW8g6sTEHm\ngg94O9Q4WMr12fin3u+VWJQO4DHvAtZ75MHy8hhkhg5LWgxyzHR5VhyWL5owPbwT\ndsN3UIXCbocYY50o2h0+McpiKR9i7EdvCHxHUXLWIFSazXjz4QHZew+Q5LFzFvQM\n+JiTJE8JjHgm9xc691cwCsECgYBlp9OV2yf99xoEkuZgCca+paVWwKUu8G/D3sat\nLyk2o0t2p7SFvhkZ0wyBEOh6pVtdz0mJMqEWgMdkHq64CkR5psE/dJUeEIEZJBAW\n4IC9YWzGtXBIpdjsFMeVrLTRYXg11p0zilMtdE8PuIjFYs2eEu2ZpBt7QtKw7Qw3\nriIbWQKBgCqVWsRu5K3UWC+uw7chVibneMbeGBEOjfi+ZndUMqTeYpdTa6KMvzOR\n6GnuUGoiUGMsT0HqUvYQRTaRDV7xlwdlgNRXkVbm0QOdsiIdoOgeFYv7TDdPFKBB\nTEoauFZCGKuj9yq0/Zlz0dy2N6Qa1H+JGM+Q8vx9ZrGVR1UgUgvN\n-----END RSA PRIVATE KEY-----\n"
      allow(subject).to receive(:command_exists?).and_return(true)
      allow(subject).to receive(:cmd_exec).and_return('ldap_bind: Invalid credentials (49)')
      allow(subject).to receive(:file_exist?).and_return(true)
      allow(subject).to receive(:read_file).and_return(key)
      expect(subject.get_idp_keys(nil, nil, nil, nil, nil).map { |item| item.to_s }).to eq([pkcs8_key])
    end
  end

  context 'idp cert' do
    it 'fails when bin not found' do
      allow(subject).to receive(:command_exists?).and_return(false)
      expect(subject.get_idp_certs(nil, nil, nil, nil, nil)).to be_nil
    end
    it 'gives back nil on failed command' do
      allow(subject).to receive(:command_exists?).and_return(true)
      allow(subject).to receive(:cmd_exec).and_return('ldap_bind: Invalid credentials (49)')
      allow(subject).to receive(:file_exist?).and_return(false)
      expect(subject.get_idp_certs(nil, nil, nil, nil, nil)).to be_nil
    end
    cert = "MIID/jCCAuagAwIBAgIJAOB8jHdnp6t0MA0GCSqGSIb3DQEBCwUAMIGgMQsw\n CQYDVQQDDAJDQTEXMBUGCgmSJomT8ixkARkWB3ZzcGhlcmUxFTATBgoJkiaJk/IsZAEZFgVsb2Nhb\n DELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExIjAgBgNVBAoMGXBob3Rvbi1tYWNoaW\n 5lLnJhZ2Vkb21haW4xGzAZBgNVBAsMElZNd2FyZSBFbmdpbmVlcmluZzAeFw0yMjA0MTYxMjA2NDB\n aFw0zMjA0MTAxMjE2MjBaMBgxFjAUBgNVBAMMDXNzb3NlcnZlclNpZ24wggEiMA0GCSqGSIb3DQEB\n AQUAA4IBDwAwggEKAoIBAQC1VLel1LcI9QtXriWxvQizqJUUqp8AmQo58nqbsiMrK8/32Qif+YspN\n UuhcOflo8H0QA3BIu+Wk3AD6V4Tvokw2NKCNE9xZGHEVGrL5aqlNNSOOP7BAyEFeICSrtVDdEJlvC\n vsWU6/lUWX7Z7Di/FFJT2g1K7g25f3fKhN73fMEOAXdbTpPrSja/xFNA9Qup9WrIUyMNxU66ewecA\n VNibtuoTB1NwYrsgUfr1J8S8AsBy5GDat0aZDTiaOjcLxNIISwb4Zq5QCXIC6zEUOXBTeZNrZvvaD\n bskeNOkW6gMkU6599jenxkoAB45E+Xk8E1RH/lB0yLD4r4jaUVu7APwJAgMBAAGjgcEwgb4wCwYDV\n R0PBAQDAgXgMCQGA1UdEQQdMBuCGXBob3Rvbi1tYWNoaW5lLnJhZ2Vkb21haW4wHQYDVR0OBBYEFD\n E+6QdUMcOeMwo0HWvgd8IuU+YbMB8GA1UdIwQYMBaAFCIsHxyxZY6GVVayBTfUOZPflwtYMEkGCCs\n GAQUFBwEBBD0wOzA5BggrBgEFBQcwAoYtaHR0cHM6Ly9waG90b24tbWFjaGluZS5yYWdlZG9tYWlu\n L2FmZC92ZWNzL2NhMA0GCSqGSIb3DQEBCwUAA4IBAQCTOd+JMMPty+W91ixxY3w4NjHMO9SaXidu0\n d3c1EHLYjyCeztznKVwb9+f6i3UBAC6zeEaXlnqA2/LwTaBv5ynFCbUyrqxPxBoYRukuXexd2NZ6W\n mTmRyHRjahea9/Ctma9CE6ll1pu6ujQTvdlsyQ74AVu2l4nu09T77uMAGXKELDxM6wv02krq7A5uG\n 8U992pTv53wz3q/0AEF83Vi5Dj7zcVPQJCcoe71viJ3Ug0f0BGSeNKCjy1E1Lp2UDnuzOu0G5lOP8\n BsbFHnk0uLk3Lms7EicPjFR71wd19RpAPe1DLnejEJ6jprOyakHAXhV/cNOQF0vix5Dq7m35+fh2"
    # has different spacing for newlines
    returned_cert = "-----BEGIN CERTIFICATE-----\nMIID/jCCAuagAwIBAgIJAOB8jHdnp6t0MA0GCSqGSIb3DQEBCwUAMIGgMQswCQYD\nVQQDDAJDQTEXMBUGCgmSJomT8ixkARkWB3ZzcGhlcmUxFTATBgoJkiaJk/IsZAEZ\nFgVsb2NhbDELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExIjAgBgNV\nBAoMGXBob3Rvbi1tYWNoaW5lLnJhZ2Vkb21haW4xGzAZBgNVBAsMElZNd2FyZSBF\nbmdpbmVlcmluZzAeFw0yMjA0MTYxMjA2NDBaFw0zMjA0MTAxMjE2MjBaMBgxFjAU\nBgNVBAMMDXNzb3NlcnZlclNpZ24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK\nAoIBAQC1VLel1LcI9QtXriWxvQizqJUUqp8AmQo58nqbsiMrK8/32Qif+YspNUuh\ncOflo8H0QA3BIu+Wk3AD6V4Tvokw2NKCNE9xZGHEVGrL5aqlNNSOOP7BAyEFeICS\nrtVDdEJlvCvsWU6/lUWX7Z7Di/FFJT2g1K7g25f3fKhN73fMEOAXdbTpPrSja/xF\nNA9Qup9WrIUyMNxU66ewecAVNibtuoTB1NwYrsgUfr1J8S8AsBy5GDat0aZDTiaO\njcLxNIISwb4Zq5QCXIC6zEUOXBTeZNrZvvaDbskeNOkW6gMkU6599jenxkoAB45E\n+Xk8E1RH/lB0yLD4r4jaUVu7APwJAgMBAAGjgcEwgb4wCwYDVR0PBAQDAgXgMCQG\nA1UdEQQdMBuCGXBob3Rvbi1tYWNoaW5lLnJhZ2Vkb21haW4wHQYDVR0OBBYEFDE+\n6QdUMcOeMwo0HWvgd8IuU+YbMB8GA1UdIwQYMBaAFCIsHxyxZY6GVVayBTfUOZPf\nlwtYMEkGCCsGAQUFBwEBBD0wOzA5BggrBgEFBQcwAoYtaHR0cHM6Ly9waG90b24t\nbWFjaGluZS5yYWdlZG9tYWluL2FmZC92ZWNzL2NhMA0GCSqGSIb3DQEBCwUAA4IB\nAQCTOd+JMMPty+W91ixxY3w4NjHMO9SaXidu0d3c1EHLYjyCeztznKVwb9+f6i3U\nBAC6zeEaXlnqA2/LwTaBv5ynFCbUyrqxPxBoYRukuXexd2NZ6WmTmRyHRjahea9/\nCtma9CE6ll1pu6ujQTvdlsyQ74AVu2l4nu09T77uMAGXKELDxM6wv02krq7A5uG8\nU992pTv53wz3q/0AEF83Vi5Dj7zcVPQJCcoe71viJ3Ug0f0BGSeNKCjy1E1Lp2UD\nnuzOu0G5lOP8BsbFHnk0uLk3Lms7EicPjFR71wd19RpAPe1DLnejEJ6jprOyakHA\nXhV/cNOQF0vix5Dq7m35+fh2\n-----END CERTIFICATE-----\n"
    it 'gives back cert on command success' do
      command_output = "dn: cn=TenantCredential-1,cn=vsphere.local,cn=Tenants,cn=IdentityManager,cn=Se\n rvices,dc=vsphere,dc=local\nuserCertificate:: #{cert}"
      allow(subject).to receive(:command_exists?).and_return(true)
      allow(subject).to receive(:cmd_exec).and_return(command_output)
      expect(subject.get_idp_certs(nil, nil, nil, nil, nil).map { |item| item.to_s }).to eq([returned_cert])
    end
    it 'gives back cert on command success with multiple user certs' do
      cert2 = "MIIEKzCCAxOgAwIBAgIJAP2y9h6OyvQ4MA0GCSqGSIb3DQEBCwUAMIGgMQsw\n CQYDVQQDDAJDQTEXMBUGCgmSJomT8ixkARkWB3ZzcGhlcmUxFTATBgoJkiaJk/IsZAEZFgVsb2Nhb\n DELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExIjAgBgNVBAoMGXBob3Rvbi1tYWNoaW\n 5lLnJhZ2Vkb21haW4xGzAZBgNVBAsMElZNd2FyZSBFbmdpbmVlcmluZzAeFw0yMjA0MTMxMjE2MjB\n aFw0zMjA0MTAxMjE2MjBaMIGgMQswCQYDVQQDDAJDQTEXMBUGCgmSJomT8ixkARkWB3ZzcGhlcmUx\n FTATBgoJkiaJk/IsZAEZFgVsb2NhbDELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExI\n jAgBgNVBAoMGXBob3Rvbi1tYWNoaW5lLnJhZ2Vkb21haW4xGzAZBgNVBAsMElZNd2FyZSBFbmdpbm\n VlcmluZzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKWeLiqdCHm7eOMLFZciwHd0XrI\n xNUlYBnAn5OzvxhuTcp0YIatF+FMugrCsrh8TgwegEPAso+VgTlTPBqGELIQgIJzcBwYU+/V7LhlE\n noe96YzATg2P+yzhfJk12l8b6pUSgY6toPrdxYSdhVxJdejH0h7zJj4JaC2hqKdgccLXcoEBJKr5R\n RhcwunmBnGlKSJnx2/c86O+tY4YD5/cJtCJZ4bOBdBCkDAxkFplTxy0ALzwKaq9zAydC/0Opgk7u2\n 5JphrWgRXAFbWdVHuR3HNpcndATIcHUzbnIGXzyOTi3Q+MhwglsTuRDL7mTJxgQvIA5Z7zBIjgqcr\n r+CUVLbcCAwEAAaNmMGQwHQYDVR0OBBYEFCIsHxyxZY6GVVayBTfUOZPflwtYMB8GA1UdEQQYMBaB\n DmVtYWlsQGFjbWUuY29thwR/AAABMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/AgEAM\n A0GCSqGSIb3DQEBCwUAA4IBAQA7+/cRuk2wQ6a7ORBaxAKhkKJ8oHVooEgGZaR1WADC63JePK06pg\n WA7dqo6tIs33dW4Mqbb0RVgX1CbrMrUatHuybIx3c6zOLAU8gpsW7V0NqPv9T/dLnZWGMFP8gnSHO\n xe818wwt3R6aKnmXHI0l3KYyPm/poVsTBxe3glTeR3D0kdUokQ3Up5Wctj8dGLBO+8/kMXJWFc788\n go2nJYp6Av8w4QwfnXSWbMrar3dRXKRj77rtnhvUMSeUTQnrW4r3M5tQmXjJ1vh93zZaCOH1ZmSMp\n WZ6LtWdXKY99ENfq23F6VGlptNlLXG2Ypzpq7BDc+ql1nH7Bd5TVPz589io"
      # different spacing
      returned_cert2 = "-----BEGIN CERTIFICATE-----\nMIIEKzCCAxOgAwIBAgIJAP2y9h6OyvQ4MA0GCSqGSIb3DQEBCwUAMIGgMQswCQYD\nVQQDDAJDQTEXMBUGCgmSJomT8ixkARkWB3ZzcGhlcmUxFTATBgoJkiaJk/IsZAEZ\nFgVsb2NhbDELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExIjAgBgNV\nBAoMGXBob3Rvbi1tYWNoaW5lLnJhZ2Vkb21haW4xGzAZBgNVBAsMElZNd2FyZSBF\nbmdpbmVlcmluZzAeFw0yMjA0MTMxMjE2MjBaFw0zMjA0MTAxMjE2MjBaMIGgMQsw\nCQYDVQQDDAJDQTEXMBUGCgmSJomT8ixkARkWB3ZzcGhlcmUxFTATBgoJkiaJk/Is\nZAEZFgVsb2NhbDELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExIjAg\nBgNVBAoMGXBob3Rvbi1tYWNoaW5lLnJhZ2Vkb21haW4xGzAZBgNVBAsMElZNd2Fy\nZSBFbmdpbmVlcmluZzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKWe\nLiqdCHm7eOMLFZciwHd0XrIxNUlYBnAn5OzvxhuTcp0YIatF+FMugrCsrh8Tgweg\nEPAso+VgTlTPBqGELIQgIJzcBwYU+/V7LhlEnoe96YzATg2P+yzhfJk12l8b6pUS\ngY6toPrdxYSdhVxJdejH0h7zJj4JaC2hqKdgccLXcoEBJKr5RRhcwunmBnGlKSJn\nx2/c86O+tY4YD5/cJtCJZ4bOBdBCkDAxkFplTxy0ALzwKaq9zAydC/0Opgk7u25J\nphrWgRXAFbWdVHuR3HNpcndATIcHUzbnIGXzyOTi3Q+MhwglsTuRDL7mTJxgQvIA\n5Z7zBIjgqcrr+CUVLbcCAwEAAaNmMGQwHQYDVR0OBBYEFCIsHxyxZY6GVVayBTfU\nOZPflwtYMB8GA1UdEQQYMBaBDmVtYWlsQGFjbWUuY29thwR/AAABMA4GA1UdDwEB\n/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/AgEAMA0GCSqGSIb3DQEBCwUAA4IBAQA7\n+/cRuk2wQ6a7ORBaxAKhkKJ8oHVooEgGZaR1WADC63JePK06pgWA7dqo6tIs33dW\n4Mqbb0RVgX1CbrMrUatHuybIx3c6zOLAU8gpsW7V0NqPv9T/dLnZWGMFP8gnSHOx\ne818wwt3R6aKnmXHI0l3KYyPm/poVsTBxe3glTeR3D0kdUokQ3Up5Wctj8dGLBO+\n8/kMXJWFc788go2nJYp6Av8w4QwfnXSWbMrar3dRXKRj77rtnhvUMSeUTQnrW4r3\nM5tQmXjJ1vh93zZaCOH1ZmSMpWZ6LtWdXKY99ENfq23F6VGlptNlLXG2Ypzpq7BD\nc+ql1nH7Bd5TVPz589io\n-----END CERTIFICATE-----\n"
      command_output = "dn: cn=TenantCredential-1,cn=vsphere.local,cn=Tenants,cn=IdentityManager,cn=Se\n rvices,dc=vsphere,dc=local\nuserCertificate:: #{cert}\nuserCertificate:: #{cert2}"
      allow(subject).to receive(:command_exists?).and_return(true)
      allow(subject).to receive(:cmd_exec).and_return(command_output)
      expect(subject.get_idp_certs(nil, nil, nil, nil, nil).map { |item| item.to_s }).to eq([returned_cert, returned_cert2])
    end
    it 'gives back cert on legacy file read' do
      cert = "-----BEGIN CERTIFICATE-----\n#{cert}\n-----END CERTIFICATE-----".gsub("\n ", "\n")
      allow(subject).to receive(:command_exists?).and_return(true)
      allow(subject).to receive(:cmd_exec).and_return('ldap_bind: Invalid credentials (49)')
      allow(subject).to receive(:file_exist?).and_return(true)
      allow(subject).to receive(:read_file).and_return(cert)
      expect(subject.get_idp_certs(nil, nil, nil, nil, nil).map { |item| item.to_s }).to eq([returned_cert])
    end
  end

  context 'sts key' do
    it 'fails when bin not found and file not found' do
      allow(subject).to receive(:command_exists?).and_return(false)
      allow(subject).to receive(:file_exist?).and_return(false)
      expect(subject.get_aes_keys(nil, nil, nil, nil, nil)).to be_nil
    end
    it 'gives back nil on failed command' do
      allow(subject).to receive(:command_exists?).and_return(true)
      allow(subject).to receive(:cmd_exec).and_return('ldap_bind: Invalid credentials (49)')
      allow(subject).to receive(:file_exist?).and_return(false)
      expect(subject.get_aes_keys(nil, nil, nil, nil, nil)).to be_nil
    end
    it 'gives back key on command success' do
      key = ']E6"Jg7V}d{!Q:Lh'
      command_output = "dn: cn=vsphere.local,cn=Tenants,cn=IdentityManager,cn=Services,dc=vsphere,dc=l\n ocal\nvmwSTSTenantKey: ]E6\"Jg7V}d{!Q:Lh"
      allow(subject).to receive(:command_exists?).and_return(true)
      allow(subject).to receive(:cmd_exec).and_return(command_output)
      allow(subject).to receive(:file_exist?).and_return(false)
      expect(subject.get_aes_keys(nil, nil, nil, nil, nil)).to eq([key])
    end
    it 'gives back key on command success with aes key file' do
      key = ']E6"Jg7V}d{!Q:Lh'
      key2 = 'ac20416a5850df52f1bf889440995871ba52984a893dbe44fd71c5c768aea3be'
      command_output = "dn: cn=vsphere.local,cn=Tenants,cn=IdentityManager,cn=Services,dc=vsphere,dc=l\n ocal\nvmwSTSTenantKey: ]E6\"Jg7V}d{!Q:Lh"
      allow(subject).to receive(:command_exists?).and_return(true)
      allow(subject).to receive(:cmd_exec).and_return(command_output)
      allow(subject).to receive(:file_exist?).and_return(true)
      allow(subject).to receive(:read_file).and_return(key2)
      expect(subject.get_aes_keys(nil, nil, nil, nil, nil)).to eq([key, key2])
    end
  end
end
