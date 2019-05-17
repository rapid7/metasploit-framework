## Vulnerable Application

Many devices produced by Ubiquiti are affected by this issue.

## Verification Steps

  1. Locate a network known or suspected to house Ubiquiti devices
  2. Start msfconsole
  3. Do: `use auxiliary/scanner/ubiquiti_discovery`
  4. Do: `set RHOSTS <some_targets>`
  5. Do: `run`

## Scenarios

  An example run against a Ubiquiti EdgeRouter-X:


  ```
  msf5 auxiliary(scanner/ubiquiti/ubiquiti_discover) > run
  [+] 192.168.1.1:10001 Ubiquiti Discovery metadata: {"ips"=>["192.168.0.1", "192.168.1.1"], "macs"=>["80:2a:a8:df:aa:bb", "f8:1e:df:f8:aa:bb"], "name"=>"ubnt", "model_short"=>"ER-X", "firmware"=>"EdgeRouter.ER-e50.v1.9.7+hotfix.4.5024279.171006.0255"}
  ```
