# This file maps the files within `metasploit-framework.wiki/` to the navigational menu
# Modify this file to change the doc site's navigation/hierarchy

# @param prefix [String] The prefix to remove from a string
# @return [proc<String, String>] When called with a string, the returned string has the prefix removed
def without_prefix(prefix)
  proc { |value| value.sub(/^#{prefix}/, '') }
end

=begin
Modify `NAVIGATION_CONFIG` to add additional items to the wiki site.
The two support options are:

1) If you are adding a new wiki page, which won't appear in msfconsole by default:

- Add your new page to `metasploit-framework.wiki`
- Add a new entry to NAVIGATION_CONFIG:
```ruby
{
  path: 'My-New-Page.md'
}
```

The title will be automatically derived from the markdown file. If you wish to override this title, use:

```ruby
{
  path: 'My-New-Page.md',
  title: 'Custom title for navigation link'
}
```

You can also programmatically change titles with procs, i.e. using the `without_prefix` helper to generate
a title from the filename with a being prefix removed:

```ruby
{
  nav_order: 7,
  path: 'Metasploit-Guide-PostgreSQL.md',
  title: without_prefix('Metasploit Guide ')
}
```

2) If you are embedding existing Metasploit module documentation into the wiki site, use relative paths:

```ruby
{
  path: '../../documentation/modules/auxiliary/admin/kerberos/forge_ticket.md',
  title: 'Silver and golden tickets'
}
```

These module docs will appear in msfconsole as well as the generated docs site. Note that msfconsole does not
support Mermaid syntax - used for generating sequence diagrams/charts/etc on the rendered docs site.

=end
NAVIGATION_CONFIG = [
  {
    path: 'Home.md',
    nav_order: 1
  },
  {
    path: 'Code-Of-Conduct.md',
    nav_order: 2
  },
  {
    path: 'Modules.md',
    title: 'Modules',
    nav_order: 3
  },
  {
    title: 'Pentesting',
    folder: 'pentesting',
    nav_order: 4,
    children: [
      {
        path: 'Metasploit-Guide-Setting-Module-Options.md',
        nav_order: 1,
        title: without_prefix('Metasploit Guide ')
      },
      {
        path: 'Metasploit-Guide-Upgrading-Shells-to-Meterpreter.md',
        nav_order: 2,
        title: without_prefix('Metasploit Guide ')
      },
      {
        nav_order: 3,
        path: 'Metasploit-Guide-Post-Gather-Modules.md',
        title: without_prefix('Metasploit Guide ')
      },
      {
        nav_order: 5,
        path: 'Metasploit-Guide-Kubernetes.md',
        title: without_prefix('Metasploit Guide ')
      },
      {
        nav_order: 5,
        path: 'Metasploit-Guide-HTTP.md',
        title: 'HTTP + HTTPS'
      },
      {
        nav_order: 6,
        path: 'Metasploit-Guide-MySQL.md',
        title: without_prefix('Metasploit Guide ')
      },
      {
        nav_order: 7,
        path: 'Metasploit-Guide-PostgreSQL.md',
        title: without_prefix('Metasploit Guide ')
      },
      {
        nav_order: 8,
        path: 'Metasploit-Guide-SMB.md',
        title: without_prefix('Metasploit Guide ')
      },
      {
        nav_order: 9,
        path: 'Metasploit-Guide-SSH.md',
        title: without_prefix('Metasploit Guide ')
      },
      {
        nav_order: 10,
        path: 'Metasploit-Guide-WinRM.md',
        title: without_prefix('Metasploit Guide ')
      },

      {
        nav_order: 11,
        path: 'Metasploit-Guide-MSSQL.md',
        title: without_prefix('Metasploit Guide ')
      },
      {
        nav_order: 12,
        path: 'Metasploit-Guide-LDAP.md',
        title: without_prefix('Metasploit Guide ')
      },

      {
        title: 'Active Directory',
        folder: 'active-directory',
        nav_order: 13,
        children: [
          {
            title: 'Kerberos',
            folder: 'kerberos',
            children: [
              {
                path: 'kerberos/overview.md',
                title: 'Overview',
                nav_order: 0
              },
              {
                path: 'kerberos/service_authentication.md',
                title: 'Authenticating to SMB/WinRM/etc',
                nav_order: 1
              },
              {
                path: '../../documentation/modules/auxiliary/scanner/kerberos/kerberos_login.md',
                title: 'Kerberos login enumeration and bruteforcing',
                nav_order: 2
              },
              {
                path: '../../documentation/modules/auxiliary/admin/kerberos/get_ticket.md',
                title: 'Get Ticket granting tickets and service tickets',
                nav_order: 3,
              },
              {
                path: '../../documentation/modules/auxiliary/admin/kerberos/forge_ticket.md',
                title: 'Forging tickets',
              },
              {
                path: '../../documentation/modules/auxiliary/admin/kerberos/inspect_ticket.md',
                title: 'Inspecting tickets',
              },
              {
                path: 'kerberos/kerberoasting.md',
                title: 'Kerberoasting',
              },
              {
                path: '../../documentation/modules/auxiliary/admin/kerberos/keytab.md',
                title: 'Keytab support and decrypting wireshark traffic'
              },
              {
                path: '../../documentation/modules/auxiliary/admin/kerberos/ticket_converter.md',
                title: 'Converting kirbi and ccache files'
              },
              {
                path: '../../documentation/modules/auxiliary/admin/ldap/rbcd.md',
                title: 'RBCD - Resource-based constrained delegation'
              }
            ]
          },
          {
            title: 'AD CS',
            folder: 'ad-certificates',
            children: [
              {
                path: 'ad-certificates/overview.md',
                title: 'Overview',
                nav_order: 0
              },
              {
                path: 'ad-certificates/Attacking-AD-CS-ESC-Vulnerabilities.md',
                title: 'Attacking AD CS ESC Vulnerabilities Using Metasploit',
                nav_order: 1
              },
              {
                path: '../../documentation/modules/auxiliary/gather/ldap_esc_vulnerable_cert_finder.md',
                title: 'Vulnerable cert finder',
                nav_order: 2
              },
              {
                path: '../../documentation/modules/auxiliary/admin/ldap/ad_cs_cert_template.md',
                title: 'Manage certificate templates'
              },
              {
                path: '../../documentation/modules/auxiliary/admin/dcerpc/icpr_cert.md',
                title: 'Request certificates'
              }
            ]
          }
        ]
      },
    ]
  },
  {
    title: 'Using Metasploit',
    folder: 'using-metasploit',
    nav_order: 5,
    children: [
      {
        title: 'Getting Started',
        folder: 'getting-started',
        nav_order: 1,
        children: [
          {
            path: 'Nightly-Installers.md',
            nav_order: 1
          },
          {
            path: 'Reporting-a-Bug.md',
            nav_order: 4
          },
        ]
      },
      {
        title: 'Basics',
        folder: 'basics',
        nav_order: 2,
        children: [
          {
            path: 'Using-Metasploit.md',
            title: 'Running modules',
            nav_order: 2
          },
          {
            path: 'How-to-use-a-Metasploit-module-appropriately.md',
            nav_order: 3
          },
          {
            path: 'How-payloads-work.md',
            nav_order: 4
          },
          {
            path: 'Module-Documentation.md',
            nav_order: 5
          },
          {
            path: 'How-to-use-a-reverse-shell-in-Metasploit.md',
            nav_order: 6
          },
          {
            path: 'How-to-use-msfvenom.md',
            nav_order: 7
          }
        ]
      },
      {
        title: 'Intermediate',
        folder: 'intermediate',
        nav_order: 3,
        children: [
          {
            path: 'Evading-Anti-Virus.md'
          },
          {
            path: 'Payload-UUID.md'
          },
          {
            path: 'Running-Private-Modules.md'
          },
          {
            path: 'Exploit-Ranking.md'
          },
          {
            path: 'Pivoting-in-Metasploit.md'
          },
          {
            path: 'Hashes-and-Password-Cracking.md'
          },
          {
            old_wiki_path: 'msfdb:-Database-Features-&-How-to-Set-up-a-Database-for-Metasploit.md',
            path: 'Metasploit-Database-Support.md',
            title: 'Database Support'
          },
          {
            path: 'How-To-Use-Plugins.md',
            title: 'Metasploit Plugins',
          }
        ]
      },
      {
        title: 'Advanced',
        folder: 'advanced',
        nav_order: 4,
        children: [
          {
            path: 'Metasploit-Web-Service.md'
          },
          {
            title: 'Meterpreter',
            folder: 'meterpreter',
            children: [
              {
                path: 'Meterpreter.md',
                title: 'Overview',
                nav_order: 1
              },
              {
                path: 'Meterpreter-Transport-Control.md',
                title: without_prefix('Meterpreter ')
              },
              {
                path: 'Meterpreter-Unicode-Support.md',
                title: without_prefix('Meterpreter ')
              },
              {
                path: 'Meterpreter-Paranoid-Mode.md',
                title: without_prefix('Meterpreter ')
              },
              {
                path: 'The-ins-and-outs-of-HTTP-and-HTTPS-communications-in-Meterpreter-and-Metasploit-Stagers.md'
              },
              {
                path: 'Meterpreter-Timeout-Control.md',
                title: without_prefix('Meterpreter ')
              },
              {
                path: 'Meterpreter-Wishlist.md',
                title: without_prefix('Meterpreter ')
              },
              {
                path: 'Meterpreter-Sleep-Control.md',
                title: without_prefix('Meterpreter ')
              },
              {
                path: 'Meterpreter-Configuration.md',
                title: without_prefix('Meterpreter ')
              },
              {
                path: 'Meterpreter-Reliable-Network-Communication.md',
                title: without_prefix('Meterpreter ')
              },
              {
                path: 'Debugging-Dead-Meterpreter-Sessions.md'
              },
              {
                path: 'Meterpreter-HTTP-Communication.md',
                title: without_prefix('Meterpreter ')
              },
              {
                path: 'Meterpreter-Stageless-Mode.md',
                title: without_prefix('Meterpreter ')
              },
              {
                path: 'Meterpreter-Debugging-Meterpreter-Sessions.md',
                title: without_prefix('Meterpreter ')
              },
              {
                path: 'Meterpreter-ExecuteBof-Command.md',
                title: without_prefix('Meterpreter ')
              },
              {
                path: 'Meterpreter-Reg-Command.md',
                title: without_prefix('Meterpreter ')
              },
              {
                path: 'How-to-get-started-with-writing-a-Meterpreter-script.md'
              },
              {
                path: 'Powershell-Extension.md'
              },
              {
                path: 'Python-Extension.md'
              },
            ]
          },
          {
            title: 'RPC',
            folder: 'RPC',
            children: [
              {
                path: 'How-to-use-Metasploit-Messagepack-RPC.md'
              },
              {
                path: 'How-to-use-Metasploit-JSON-RPC.md'
              },
            ]
          },
        ]
      },
      {
        title: 'Other',
        folder: 'other',
        children: [
          {
            title: 'Oracle Support',
            folder: 'oracle-support',
            children: [
              {
                path: 'Oracle-Usage.md'
              },
              {
                path: 'How-to-get-Oracle-Support-working-with-Kali-Linux.md'
              },
            ]
          },
          {
            path: 'Information-About-Unmet-Browser-Exploit-Requirements.md'
          },
          {
            path: 'Why-CVE-is-not-available.md'
          },
          {
            path: 'How-to-use-the-Favorite-command.md'
          },
        ]
      },
    ]
  },
  {
    title: 'Development',
    folder: 'development',
    nav_order: 6,
    children: [
      {
        title: 'Get Started ',
        folder: 'get-started',
        nav_order: 1,
        children: [
          {
            path: 'Contributing-to-Metasploit.md',
            nav_order: 1
          },
          {
            path: 'Creating-Your-First-PR.md',
            nav_order: 2
          },
          {
            path: 'dev/Setting-Up-a-Metasploit-Development-Environment.md',
            nav_order: 3
          },
          {
            path: 'Sanitizing-PCAPs.md',
            nav_order: 4
          },
          {
            old_wiki_path: "Navigating-and-Understanding-Metasploit's-Codebase.md",
            path: 'Navigating-and-Understanding-Metasploits-Codebase.md',
            title: 'Navigating the codebase'
          },
          {
            title: 'Git',
            folder: 'git',
            children: [
              {
                path: 'Keeping-in-sync-with-rapid7-master.md'
              },
              {
                path: 'git/Git-cheatsheet.md'
              },
              {
                path: 'git/Using-Git.md'
              },
              {
                path: 'git/Git-Reference-Sites.md'
              },
              {
                path: 'Remote-Branch-Pruning.md'
              },
            ]
          },
        ]
      },
      {
        title: 'Developing Modules',
        folder: 'developing-modules',
        nav_order: 2,
        children: [
          {
            title: 'Guides',
            folder: 'guides',
            nav_order: 2,
            children: [
              {
                path: 'How-to-get-started-with-writing-a-post-module.md',
                title: 'Writing a post module'
              },
              {
                path: 'Get-Started-Writing-an-Exploit.md',
                title: 'Writing an exploit'
              },
              {
                path: 'How-to-write-a-browser-exploit-using-HttpServer.md',
                title: 'Writing a browser exploit'
              },
              {
                title: 'Scanners',
                folder: 'scanners',
                nav_order: 2,
                children: [
                  {
                    path: 'How-to-write-a-HTTP-LoginScanner-Module.md',
                    title: 'Writing a HTTP LoginScanner'
                  },
                  {
                    path: 'Creating-Metasploit-Framework-LoginScanners.md',
                    title: 'Writing an FTP LoginScanner'
                  },
                ]
              },
              {
                path: 'How-to-get-started-with-writing-an-auxiliary-module.md',
                title: 'Writing an auxiliary module'
              },
              {
                path: 'How-to-use-command-stagers.md'
              },
              {
                path: 'How-to-use-fetch-payloads.md',
                title: 'How to use Fetch Payloads'
              },
              {
                old_wiki_path: 'How-to-write-a-check()-method.md',
                path: 'How-to-write-a-check-method.md'
              },
              {
                path: 'How-to-check-Microsoft-patch-levels-for-your-exploit.md'
              },
              {
                path: "How-to-write-a-cmd-injection-module.md"
              }
            ]
          },
          {
            title: 'Libraries',
            folder: 'libraries',
            children: [
              {
                path: 'API.md',
                nav_order: 0
              },
              {
                title: 'Compiling C',
                folder: 'c',
                children: [
                  {
                    path: 'How-to-use-Metasploit-Framework-Compiler-Windows-to-compile-C-code.md',
                    title: 'Overview',
                    nav_order: 1
                  },
                  {
                    path: 'How-to-XOR-with-Metasploit-Framework-Compiler.md',
                    title: 'XOR Support'
                  },
                  {
                    path: 'How-to-decode-Base64-with-Metasploit-Framework-Compiler.md',
                    title: 'Base64 Support'
                  },
                  {
                    path: 'How-to-decrypt-RC4-with-Metasploit-Framework-Compiler.md',
                    title: 'RC4 Support'
                  },
                ]
              },
              {
                path: 'How-to-log-in-Metasploit.md',
                title: 'Logging'
              },
              {
                path: 'How-to-use-Railgun-for-Windows-post-exploitation.md',
                title: 'Railgun'
              },
              {
                old_wiki_path: 'How-to-zip-files-with-Msf-Util-EXE.to_zip.md',
                path: 'How-to-zip-files-with-Msf-Util-EXE-to_zip.md',
                title: 'Zip'
              },
              {
                old_wiki_path: 'Handling-Module-Failures-with-`fail_with`.md',
                path: 'Handling-Module-Failures-with-fail_with.md',
                title: 'Fail_with'
              },
              {
                path: 'How-to-use-Msf-Auxiliary-AuthBrute-to-write-a-bruteforcer.md',
                title: 'AuthBrute'
              },
              {
                path: 'How-to-Use-the-FILEFORMAT-mixin-to-create-a-file-format-exploit.md',
                title: 'Fileformat'
              },
              {
                old_wiki_path: 'SQL-Injection-(SQLi)-Libraries.md',
                path: 'SQL-Injection-Libraries.md',
                title: 'SQL Injection'
              },
              {
                path: 'How-to-use-Powershell-in-an-exploit.md',
                title: 'Powershell'
              },
              {
                path: 'How-to-use-the-Seh-mixin-to-exploit-an-exception-handler.md',
                title: 'SEH Exploitation'
              },
              {
                path: 'How-to-use-PhpEXE-to-exploit-an-arbitrary-file-upload-bug.md',
                title: 'PhpExe'
              },
              {
                path: 'How-to-use-the-Git-mixin-to-write-an-exploit-module.md',
                title: 'Git Mixin'
              },
              {
                title: 'HTTP',
                folder: 'http',
                children: [
                  {
                    path: 'How-to-send-an-HTTP-request-using-Rex-Proto-Http-Client.md'
                  },
                  {
                    path: 'How-to-parse-an-HTTP-response.md'
                  },
                  {
                    path: 'How-to-write-a-module-using-HttpServer-and-HttpClient.md'
                  },
                  {
                    path: 'How-to-Send-an-HTTP-Request-Using-HttpClient.md'
                  },
                  {
                    path: 'How-to-write-a-browser-exploit-using-BrowserExploitServer.md',
                    title: 'BrowserExploitServer'
                  },
                ]
              },
              {
                title: 'Deserialization',
                folder: 'deserialization',
                children: [
                  {
                    path: 'Dot-Net-Deserialization.md'
                  },
                  {
                    old_wiki_path: 'Generating-`ysoserial`-Java-serialized-objects.md',
                    path: 'Generating-ysoserial-Java-serialized-objects.md',
                    title: 'Java Deserialization'
                  }
                ]
              },
              {
                title: 'Obfuscation',
                folder: 'obfuscation',
                children: [
                  {
                    path: 'How-to-obfuscate-JavaScript-in-Metasploit.md',
                    title: 'JavaScript Obfuscation'
                  },
                  {
                    path: 'How-to-use-Metasploit-Framework-Obfuscation-CRandomizer.md',
                    title: 'C Obfuscation'
                  },
                ]
              },
              {
                path: 'How-to-use-the-Msf-Exploit-Remote-Tcp-mixin.md',
                title: 'TCP'
              },
              {
                path: 'How-to-do-reporting-or-store-data-in-module-development.md',
                title: 'Reporting and Storing Data'
              },
              {
                path: 'How-to-use-WbemExec-for-a-write-privilege-attack-on-Windows.md',
                title: 'WbemExec'
              },
              {
                title: 'SMB Library',
                folder: 'smb_library',
                children: [
                  {
                    path: 'What-my-Rex-Proto-SMB-Error-means.md'
                  },
                  {
                    path: 'Guidelines-for-Writing-Modules-with-SMB.md'
                  },
                ]
              },
              {
                path: 'Using-ReflectiveDLL-Injection.md',
                title: 'ReflectiveDLL Injection'
              },
              {
                path: 'How-to-cleanup-after-module-execution.md',
                title: 'Cleanup'
              },
            ]
          },
          {
            title: 'External Modules',
            folder: 'external-modules',
            nav_order: 3,
            children: [
              {
                path: 'Writing-External-Metasploit-Modules.md',
                title: 'Overview',
                nav_order: 1
              },
              {
                path: 'Writing-External-Python-Modules.md',
                title: 'Writing Python Modules'
              },
              {
                path: 'Writing-External-GoLang-Modules.md',
                title: 'Writing GoLang Modules'
              },
            ]
          },
          {
            title: 'Module metadata',
            folder: 'module-metadata',
            nav_order: 3,
            children: [
              {
                path: 'How-to-use-datastore-options.md'
              },
              {
                path: 'Module-Reference-Identifiers.md'
              },
              {
                old_wiki_path: 'Definition-of-Module-Reliability,-Side-Effects,-and-Stability.md',
                path: 'Definition-of-Module-Reliability-Side-Effects-and-Stability.md'
              },
            ]
          }
        ]
      },
      {
        title: 'Maintainers',
        folder: 'maintainers',
        children: [
          {
            title: 'Process',
            folder: 'process',
            children: [
              {
                path: 'Guidelines-for-Accepting-Modules-and-Enhancements.md'
              },
              {
                path: 'How-to-deprecate-a-Metasploit-module.md'
              },
              {
                path: 'Landing-Pull-Requests.md'
              },
              {
                path: 'Assigning-Labels.md'
              },
              {
                path: 'Adding-Release-Notes-to-PRs.md',
                title: 'Release Notes'
              },
              {
                path: 'Rolling-back-merges.md'
              },
              {
                path: 'Unstable-Modules.md'
              },
            ]
          },
          {
            path: 'Committer-Rights.md'
          },
          {
            title: 'Ruby Gems',
            folder: 'ruby-gems',
            children: [
              {
                path: 'How-to-add-and-update-gems-in-metasploit-framework.md',
                title: 'Adding and Updating'
              },
              {
                old_wiki_path: 'Testing-Rex-and-other-Gem-File-Updates-With-Gemfile.local-and-Gemfile.local.example.md',
                path: 'Using-local-gems.md',
                title: 'Using local Gems'
              },
              {
                path: 'Merging-Metasploit-Payload-Gem-Updates.md'
              },
            ]
          },
          {
            path: 'Committer-Keys.md'
          },
          {
            path: 'Metasploit-Loginpalooza.md'
          },
          {
            path: 'Metasploit-Hackathons.md'
          },
          {
            path: 'Downloads-by-Version.md'
          }
        ]
      },
      {
        title: 'Quality',
        folder: 'quality',
        children: [
          {
            path: 'Style-Tips.md'
          },
          {
            path: 'Msftidy.md'
          },
          {
            path: 'Using-Rubocop.md'
          },
          {
            path: 'Common-Metasploit-Module-Coding-Mistakes.md'
          },
          {
            path: 'Writing-Module-Documentation.md'
          },
          {
            path: 'Loading-Test-Modules.md'
          },
          {
            path: 'Measuring-Metasploit-Performance.md'
          }
        ]
      },
      {
        title: 'Google Summer of Code',
        folder: 'google-summer-of-code',
        children: [
          {
            path: 'How-to-Apply-to-GSoC.md'
          },
          {
            path: 'GSoC-2017-Student-Proposal.md',
            title: without_prefix('GSoC')
          },
          {
            path: 'GSoC-2017-Project-Ideas.md',
            title: without_prefix('GSoC')
          },
          {
            path: 'GSoC-2018-Project-Ideas.md',
            title: without_prefix('GSoC')
          },
          {
            path: 'GSoC-2017-Mentor-Organization-Application.md',
            title: without_prefix('GSoC')
          },
          {
            path: 'GSoC-2019-Project-Ideas.md',
            title: without_prefix('GSoC')
          },
          {
            path: 'GSoC-2020-Project-Ideas.md',
            title: without_prefix('GSoC')
          },
          {
            path: 'GSoC-2021-Project-Ideas.md',
            title: without_prefix('GSoC')
          },
          {
            path: 'GSoC-2022-Project-Ideas.md',
            title: without_prefix('GSoC')
          },
          {
            path: 'GSoC-2023-Project-Ideas.md',
            title: without_prefix('GSoC')
          },
        ]
      },
      {
        title: 'Proposals',
        folder: 'propsals',
        children: [
          {
            path: 'Bundled-Modules-Proposal.md'
          },
          {
            path: 'MSF6-Feature-Proposals.md'
          },
          {
            old_wiki_path: 'RFC---Metasploit-URL-support.md',
            path: 'Metasploit-URL-support-proposal.md'
          },
          {
            path: 'Uberhandler.md'
          },
          {
            path: 'Work-needed-to-allow-msfdb-to-use-postgresql-common.md'
          },
          {
            path: 'Payload-Rename-Justification.md'
          },
          {
            path: 'Java-Meterpreter-Feature-Parity-Proposal.md'
          }
        ]
      },
      {
        title: 'Roadmap',
        folder: 'roadmap',
        children: [
          {
            path: 'Metasploit-Framework-Wish-List.md'
          },
          {
            path: 'Metasploit-5.0-Release-Notes.md',
            new_base_name: 'Metasploit-5-Release-Notes.md',
            title: 'Metasploit Framework 5.0 Release Notes'
          },
          {
            path: '2017-Roadmap-Review.md'
          },
          {
            path: 'Metasploit-6.0-Development-Notes.md',
            new_base_name: 'Metasploit-6-Release-Notes.md',
            title: 'Metasploit Framework 6.0 Release Notes'
          },
          {
            path: '2017-Roadmap.md'
          },
          {
            path: 'Metasploit-Breaking-Changes.md'
          },
          {
            old_wiki_path: 'Metasploit-Data-Service-Enhancements-(Goliath).md',
            path: 'Metasploit-Data-Service-Enhancements-Goliath.md',
            title: 'Metasploit Data Service'
          },
        ]
      },
    ]
  },
  {
    path: 'Contact.md',
    nav_order: 7
  },
].freeze
