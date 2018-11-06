# Change Log

## [v7.2.0](https://github.com/rapid7/nexpose-client/tree/v7.2.0) (2018-01-17)
[Full Changelog](https://github.com/rapid7/nexpose-client/compare/v7.1.1...v7.2.0)

**Closed issues:**

- list\_vuln\_exceptions returns API error [\#312](https://github.com/rapid7/nexpose-client/issues/312)
- Credentials failure after using Site.copy  [\#307](https://github.com/rapid7/nexpose-client/issues/307)
- XML serialization for VulnException incorrect due to extra whitespace  [\#304](https://github.com/rapid7/nexpose-client/issues/304)
- Nexpose timeout does not seem to work [\#299](https://github.com/rapid7/nexpose-client/issues/299)

**Merged pull requests:**

- Update vuln exceptions to use generally available API version [\#313](https://github.com/rapid7/nexpose-client/pull/313) ([mhuffman-r7](https://github.com/mhuffman-r7))
- Add a method to add common vuln status filters to report configs [\#303](https://github.com/rapid7/nexpose-client/pull/303) ([gschneider-r7](https://github.com/gschneider-r7))
- Updated for Ruby 2.4 Support [\#301](https://github.com/rapid7/nexpose-client/pull/301) ([twosevenzero](https://github.com/twosevenzero))

## [v7.1.1](https://github.com/rapid7/nexpose-client/tree/v7.1.1) (2017-09-28)
[Full Changelog](https://github.com/rapid7/nexpose-client/compare/v7.1.0...v7.1.1)

**Merged pull requests:**

- Some methods were not honoring custom Connection Timeouts [\#300](https://github.com/rapid7/nexpose-client/pull/300) ([sgreen-r7](https://github.com/sgreen-r7))

## [v7.1.0](https://github.com/rapid7/nexpose-client/tree/v7.1.0) (2017-09-26)
[Full Changelog](https://github.com/rapid7/nexpose-client/compare/v7.0.1...v7.1.0)

**Fixed bugs:**

- nsc.list\_vuln\_exceptions does not return site\_id as documented [\#250](https://github.com/rapid7/nexpose-client/issues/250)

**Closed issues:**

- Connection Timeout When Creating DynamicAssetGroup with large number of criteria [\#274](https://github.com/rapid7/nexpose-client/issues/274)
- Vulnerability Exception 'approve' function applies vulnerability exception but throws a ruby exception [\#271](https://github.com/rapid7/nexpose-client/issues/271)
- Add a global timeout parameter to Connection [\#269](https://github.com/rapid7/nexpose-client/issues/269)
- Update Example Scripts [\#244](https://github.com/rapid7/nexpose-client/issues/244)
- support for encryption for recovery [\#290](https://github.com/rapid7/nexpose-client/issues/290)

**Merged pull requests:**

- adding the ability to include a password when restoring a backup [\#298](https://github.com/rapid7/nexpose-client/pull/298) ([sgreen-r7](https://github.com/sgreen-r7))
- Allow for Starting Scan during Blackout [\#297](https://github.com/rapid7/nexpose-client/pull/297) ([sgreen-r7](https://github.com/sgreen-r7))

## [v7.0.1](https://github.com/rapid7/nexpose-client/tree/v7.0.1) (2017-09-11)
[Full Changelog](https://github.com/rapid7/nexpose-client/compare/v7.0.0...v7.0.1)

**Merged pull requests:**

- Only Cleanup!! v3 [\#295](https://github.com/rapid7/nexpose-client/pull/295) ([sgreen-r7](https://github.com/sgreen-r7))
- Revert "Only Cleanup!" [\#293](https://github.com/rapid7/nexpose-client/pull/293) ([sgreen-r7](https://github.com/sgreen-r7))
- Only Cleanup! [\#292](https://github.com/rapid7/nexpose-client/pull/292) ([sgreen-r7](https://github.com/sgreen-r7))

## [v7.0.0](https://github.com/rapid7/nexpose-client/tree/v7.0.0) (2017-08-31)
[Full Changelog](https://github.com/rapid7/nexpose-client/compare/v6.1.1...v7.0.0)

**Fixed bugs:**

- list\_discovery\_connections - engine\_id is blank when output [\#278](https://github.com/rapid7/nexpose-client/issues/278)
- Adhoc scan of hostname calls a non-existent accessor in method [\#267](https://github.com/rapid7/nexpose-client/issues/267)

**Closed issues:**

- ETA on "the ability to create VulnExceptions based on AssetGroups via the gem"? [\#281](https://github.com/rapid7/nexpose-client/issues/281)

**Merged pull requests:**

- Add nexpose-resources reference to readme [\#291](https://github.com/rapid7/nexpose-client/pull/291) ([gschneider-r7](https://github.com/gschneider-r7))
- Adding Ability to Set Connection Timeout Values [\#289](https://github.com/rapid7/nexpose-client/pull/289) ([sgreen-r7](https://github.com/sgreen-r7))
- Some additional issues found for credentials... [\#288](https://github.com/rapid7/nexpose-client/pull/288) ([bglass-r7](https://github.com/bglass-r7))
- Update for Credentials classes [\#287](https://github.com/rapid7/nexpose-client/pull/287) ([sgreen-r7](https://github.com/sgreen-r7))
- filter.rb add LIKE operator [\#286](https://github.com/rapid7/nexpose-client/pull/286) ([tnewcomb-r7](https://github.com/tnewcomb-r7))
- Added scan name to calls returning CompletedScan [\#279](https://github.com/rapid7/nexpose-client/pull/279) ([bglass-r7](https://github.com/bglass-r7))
- Bug fixes for adhoc scan with hostname and dynamic asset group description [\#276](https://github.com/rapid7/nexpose-client/pull/276) ([gschneider-r7](https://github.com/gschneider-r7))

## [v6.1.1](https://github.com/rapid7/nexpose-client/tree/v6.1.1) (2017-07-24)
[Full Changelog](https://github.com/rapid7/nexpose-client/compare/v6.1.0...v6.1.1)

## [v6.1.0](https://github.com/rapid7/nexpose-client/tree/v6.1.0) (2017-06-19)
[Full Changelog](https://github.com/rapid7/nexpose-client/compare/v6.0.0...v6.1.0)

**Closed issues:**

- Please make engine pool available in ScanData, ScanSummary. [\#277](https://github.com/rapid7/nexpose-client/issues/277)

## [v6.0.0](https://github.com/rapid7/nexpose-client/tree/v6.0.0) (2017-04-03)
[Full Changelog](https://github.com/rapid7/nexpose-client/compare/v5.3.2...v6.0.0)

**Fixed bugs:**

- Blackout always shows enabled = true [\#264](https://github.com/rapid7/nexpose-client/issues/264)

**Merged pull requests:**

- adding support for listing vuln exceptions on asset groups [\#266](https://github.com/rapid7/nexpose-client/pull/266) ([sgreen-r7](https://github.com/sgreen-r7))

## [v5.3.2](https://github.com/rapid7/nexpose-client/tree/v5.3.2) (2017-03-28)
[Full Changelog](https://github.com/rapid7/nexpose-client/compare/v5.3.1...v5.3.2)

**Fixed bugs:**

- Test Credentials method fails \(some params missing in api call\) [\#261](https://github.com/rapid7/nexpose-client/issues/261)

**Merged pull requests:**

- set blackout enabled [\#265](https://github.com/rapid7/nexpose-client/pull/265) ([dmurray-r7](https://github.com/dmurray-r7))

## [v5.3.1](https://github.com/rapid7/nexpose-client/tree/v5.3.1) (2017-03-01)
[Full Changelog](https://github.com/rapid7/nexpose-client/compare/v5.3.0...v5.3.1)

**Closed issues:**

- Allow a user to enable certificate pinning when verifying a TLS connection to a nexpose console [\#246](https://github.com/rapid7/nexpose-client/issues/246)

**Merged pull requests:**

- added specific test method for shared creds to use correct attrs [\#262](https://github.com/rapid7/nexpose-client/pull/262) ([sgreen-r7](https://github.com/sgreen-r7))

## [v5.3.0](https://github.com/rapid7/nexpose-client/tree/v5.3.0) (2017-02-14)
[Full Changelog](https://github.com/rapid7/nexpose-client/compare/v5.2.0...v5.3.0)

**Merged pull requests:**

- Update docs for Nexpose::Connection with more examples [\#259](https://github.com/rapid7/nexpose-client/pull/259) ([gschneider-r7](https://github.com/gschneider-r7))
- allow user to supply a cerificate file for trusted SSL [\#254](https://github.com/rapid7/nexpose-client/pull/254) ([jmartin-r7](https://github.com/jmartin-r7))

## [v5.2.0](https://github.com/rapid7/nexpose-client/tree/v5.2.0) (2017-01-31)
[Full Changelog](https://github.com/rapid7/nexpose-client/compare/v5.1.0...v5.2.0)

**Fixed bugs:**

- Fetch relevant filters for ReportConfig when load functions is called. [\#238](https://github.com/rapid7/nexpose-client/issues/238)
- Delete assets from sites if there is no deviceid [\#148](https://github.com/rapid7/nexpose-client/issues/148)
- bugfix/email-toAllAuthorized - use proper variable to set toAllAuthorized for Email class [\#255](https://github.com/rapid7/nexpose-client/pull/255) ([zyoutz-r7](https://github.com/zyoutz-r7))

**Closed issues:**

- SCAN\_DATE filter documentation is unclear [\#256](https://github.com/rapid7/nexpose-client/issues/256)
- Add "Remove asset from site" method for global assets \(asset linking enabled\) [\#228](https://github.com/rapid7/nexpose-client/issues/228)

**Merged pull requests:**

- Add remove\_assets\_from\_site method [\#258](https://github.com/rapid7/nexpose-client/pull/258) ([gschneider-r7](https://github.com/gschneider-r7))
- clarify filter SCAN\_DATE docs [\#257](https://github.com/rapid7/nexpose-client/pull/257) ([nbirnel](https://github.com/nbirnel))
- Update Connection\#download method to stream data [\#248](https://github.com/rapid7/nexpose-client/pull/248) ([braxtone](https://github.com/braxtone))
- Introduce PR and Issue templates, move contributing doc [\#247](https://github.com/rapid7/nexpose-client/pull/247) ([gschneider-r7](https://github.com/gschneider-r7))
- Fix extra newline characters in documentation [\#243](https://github.com/rapid7/nexpose-client/pull/243) ([braxtone](https://github.com/braxtone))
- add Connection:update\_engine [\#227](https://github.com/rapid7/nexpose-client/pull/227) ([nbirnel](https://github.com/nbirnel))

## [v5.1.0](https://github.com/rapid7/nexpose-client/tree/v5.1.0) (2016-08-26)
[Full Changelog](https://github.com/rapid7/nexpose-client/compare/v5.0.0...v5.1.0)

**Fixed bugs:**

- Loading fails for Site configured with a non-repeating Blackout. [\#225](https://github.com/rapid7/nexpose-client/issues/225)

**Merged pull requests:**

- Add Unique ID support to Asset and ExternalAsset [\#241](https://github.com/rapid7/nexpose-client/pull/241) ([gschneider-r7](https://github.com/gschneider-r7))
- first attempt for fix of hash failure of blackouts [\#226](https://github.com/rapid7/nexpose-client/pull/226) ([sgreen-r7](https://github.com/sgreen-r7))
- Use latest minor versions of Ruby in Travis-CI [\#218](https://github.com/rapid7/nexpose-client/pull/218) ([gschneider-r7](https://github.com/gschneider-r7))

## [v5.0.0](https://github.com/rapid7/nexpose-client/tree/v5.0.0) (2016-06-23)
[Full Changelog](https://github.com/rapid7/nexpose-client/compare/v4.0.5...v5.0.0)

**Fixed bugs:**

- Documentation for Email class in Common.rb [\#236](https://github.com/rapid7/nexpose-client/issues/236)

**Merged pull requests:**

- Revert changes to maintenance command URIs [\#239](https://github.com/rapid7/nexpose-client/pull/239) ([gschneider-r7](https://github.com/gschneider-r7))
- \[Issue : \#236\] : Documentation for Email class was made more concise [\#237](https://github.com/rapid7/nexpose-client/pull/237) ([snehitgajjar](https://github.com/snehitgajjar))
- Fix incorrect documentation for schedule time format [\#232](https://github.com/rapid7/nexpose-client/pull/232) ([dmurray-r7](https://github.com/dmurray-r7))

## [v4.0.5](https://github.com/rapid7/nexpose-client/tree/v4.0.5) (2016-06-02)
[Full Changelog](https://github.com/rapid7/nexpose-client/compare/v4.0.4...v4.0.5)

**Closed issues:**

- completed\_assets returns incorrect asset identifier [\#233](https://github.com/rapid7/nexpose-client/issues/233)

**Merged pull requests:**

- \#233: Fixed parsing of completed asset response to use correct asset ID [\#234](https://github.com/rapid7/nexpose-client/pull/234) ([mhuffman-r7](https://github.com/mhuffman-r7))
- api delete fix [\#230](https://github.com/rapid7/nexpose-client/pull/230) ([dmurray-r7](https://github.com/dmurray-r7))

## [v4.0.4](https://github.com/rapid7/nexpose-client/tree/v4.0.4) (2016-05-17)
[Full Changelog](https://github.com/rapid7/nexpose-client/compare/v4.0.3...v4.0.4)

## [v4.0.3](https://github.com/rapid7/nexpose-client/tree/v4.0.3) (2016-05-11)
[Full Changelog](https://github.com/rapid7/nexpose-client/compare/v4.0.2...v4.0.3)

**Fixed bugs:**

- Increase REXML::Security.entity\_expansion\_text\_limit [\#229](https://github.com/rapid7/nexpose-client/pull/229) ([sgreen-r7](https://github.com/sgreen-r7))

## [v4.0.2](https://github.com/rapid7/nexpose-client/tree/v4.0.2) (2016-05-06)
[Full Changelog](https://github.com/rapid7/nexpose-client/compare/v4.0.1...v4.0.2)

## [v4.0.1](https://github.com/rapid7/nexpose-client/tree/v4.0.1) (2016-05-06)
[Full Changelog](https://github.com/rapid7/nexpose-client/compare/v4.0.0...v4.0.1)

## [v4.0.0](https://github.com/rapid7/nexpose-client/tree/v4.0.0) (2016-05-05)
[Full Changelog](https://github.com/rapid7/nexpose-client/compare/v3.3.2...v4.0.0)

**Closed issues:**

- Allow import scan to return scan id [\#208](https://github.com/rapid7/nexpose-client/issues/208)

**Merged pull requests:**

- Add new filter and update IP address operators [\#224](https://github.com/rapid7/nexpose-client/pull/224) ([rkhalil-r7](https://github.com/rkhalil-r7))
- Allow import scan to return scan ID when available [\#223](https://github.com/rapid7/nexpose-client/pull/223) ([gschneider-r7](https://github.com/gschneider-r7))

## [v3.3.2](https://github.com/rapid7/nexpose-client/tree/v3.3.2) (2016-04-29)
[Full Changelog](https://github.com/rapid7/nexpose-client/compare/v3.3.1...v3.3.2)

**Fixed bugs:**

- Connection.past\_scans\(\) fails [\#220](https://github.com/rapid7/nexpose-client/issues/220)

**Closed issues:**

- Past Scans Throwing n API Error [\#222](https://github.com/rapid7/nexpose-client/issues/222)
- CIFS Test Authentication Can't Find the Server [\#219](https://github.com/rapid7/nexpose-client/issues/219)
- Return string and integer vulnerability id in Connection\#list\_vulns\(full = true\) [\#217](https://github.com/rapid7/nexpose-client/issues/217)

**Merged pull requests:**

- Update endpoints for getting and setting user row prefs [\#221](https://github.com/rapid7/nexpose-client/pull/221) ([sgreen-r7](https://github.com/sgreen-r7))
- Make HostOrIP\#convert more flexible on IP address range input [\#214](https://github.com/rapid7/nexpose-client/pull/214) ([gschneider-r7](https://github.com/gschneider-r7))

## [v3.3.1](https://github.com/rapid7/nexpose-client/tree/v3.3.1) (2016-04-08)
[Full Changelog](https://github.com/rapid7/nexpose-client/compare/v3.3.0...v3.3.1)

**Fixed bugs:**

- Credential test does not work because the username parameter is set incorrectly [\#215](https://github.com/rapid7/nexpose-client/issues/215)

**Closed issues:**

- Unable to retrieve proofs [\#213](https://github.com/rapid7/nexpose-client/issues/213)

**Merged pull requests:**

- Fixing variable references in the to-headers call [\#216](https://github.com/rapid7/nexpose-client/pull/216) ([mhuffman-r7](https://github.com/mhuffman-r7))

## [v3.3.0](https://github.com/rapid7/nexpose-client/tree/v3.3.0) (2016-04-06)
[Full Changelog](https://github.com/rapid7/nexpose-client/compare/v3.2.0...v3.3.0)

**Closed issues:**

- Return nexpose\_id via API using vulnid [\#210](https://github.com/rapid7/nexpose-client/issues/210)
- Adding criteria to tag. [\#209](https://github.com/rapid7/nexpose-client/issues/209)

**Merged pull requests:**

- Add method for returning the version information for each scan engine [\#212](https://github.com/rapid7/nexpose-client/pull/212) ([Red5d](https://github.com/Red5d))
- Scheduled Backup and Maintenance  [\#211](https://github.com/rapid7/nexpose-client/pull/211) ([dmurray-r7](https://github.com/dmurray-r7))

## [v3.2.0](https://github.com/rapid7/nexpose-client/tree/v3.2.0) (2016-01-20)
[Full Changelog](https://github.com/rapid7/nexpose-client/compare/v3.1.0...v3.2.0)

**Merged pull requests:**

- Windows services editor option [\#207](https://github.com/rapid7/nexpose-client/pull/207) ([kprzerwa-r7](https://github.com/kprzerwa-r7))

## [v3.1.0](https://github.com/rapid7/nexpose-client/tree/v3.1.0) (2016-01-06)
[Full Changelog](https://github.com/rapid7/nexpose-client/compare/v3.0.1...v3.1.0)

**Merged pull requests:**

- Two factor authentication [\#206](https://github.com/rapid7/nexpose-client/pull/206) ([dsadgat-r7](https://github.com/dsadgat-r7))

## [v3.0.1](https://github.com/rapid7/nexpose-client/tree/v3.0.1) (2015-12-11)
[Full Changelog](https://github.com/rapid7/nexpose-client/compare/v3.0.0...v3.0.1)

## [v3.0.0](https://github.com/rapid7/nexpose-client/tree/v3.0.0) (2015-12-11)
[Full Changelog](https://github.com/rapid7/nexpose-client/compare/v2.3.0...v3.0.0)

**Closed issues:**

- Add method to list paused scans [\#193](https://github.com/rapid7/nexpose-client/issues/193)
- Allow ad-hoc scan methods to behave similar as in UI [\#188](https://github.com/rapid7/nexpose-client/issues/188)

**Merged pull requests:**

- removing additional deprecated scan template methods [\#203](https://github.com/rapid7/nexpose-client/pull/203) ([sgreen-r7](https://github.com/sgreen-r7))
- Extract Rex::MIME dependency [\#201](https://github.com/rapid7/nexpose-client/pull/201) ([gschneider-r7](https://github.com/gschneider-r7))
- Add asset\_scan\_history method [\#198](https://github.com/rapid7/nexpose-client/pull/198) ([gschneider-r7](https://github.com/gschneider-r7))
- Add methods to retrieve paused scans [\#196](https://github.com/rapid7/nexpose-client/pull/196) ([gschneider-r7](https://github.com/gschneider-r7))
- Adhoc scan subset of assets within a site, with a different scan template and scan engine [\#195](https://github.com/rapid7/nexpose-client/pull/195) ([gschneider-r7](https://github.com/gschneider-r7))
- Remove deprecated method aliases [\#184](https://github.com/rapid7/nexpose-client/pull/184) ([gschneider-r7](https://github.com/gschneider-r7))

## [v2.3.0](https://github.com/rapid7/nexpose-client/tree/v2.3.0) (2015-12-10)
[Full Changelog](https://github.com/rapid7/nexpose-client/compare/v2.2.0...v2.3.0)

**Merged pull requests:**

- Add support for modifying the asset linking global preference [\#202](https://github.com/rapid7/nexpose-client/pull/202) ([erran-r7](https://github.com/erran-r7))

## [v2.2.0](https://github.com/rapid7/nexpose-client/tree/v2.2.0) (2015-12-01)
[Full Changelog](https://github.com/rapid7/nexpose-client/compare/v2.1.3...v2.2.0)

**Merged pull requests:**

- Add methods to enable debug/enhanced logging in the scan template. [\#197](https://github.com/rapid7/nexpose-client/pull/197) ([xliu-r7](https://github.com/xliu-r7))

## [v2.1.3](https://github.com/rapid7/nexpose-client/tree/v2.1.3) (2015-11-23)
[Full Changelog](https://github.com/rapid7/nexpose-client/compare/v2.1.2...v2.1.3)

**Merged pull requests:**

- Update vuln.rb [\#199](https://github.com/rapid7/nexpose-client/pull/199) ([rchen-r7](https://github.com/rchen-r7))
- Update documentation for list\_device\_vulns [\#194](https://github.com/rapid7/nexpose-client/pull/194) ([rchen-r7](https://github.com/rchen-r7))

## [v2.1.2](https://github.com/rapid7/nexpose-client/tree/v2.1.2) (2015-11-04)
[Full Changelog](https://github.com/rapid7/nexpose-client/compare/v2.1.1...v2.1.2)

**Closed issues:**

- import\_scan function leaves behind open file handles [\#190](https://github.com/rapid7/nexpose-client/issues/190)

**Merged pull requests:**

- Compatibility with ScanTemplateHandler port [\#192](https://github.com/rapid7/nexpose-client/pull/192) ([btrujillo-r7](https://github.com/btrujillo-r7))
- Use a block with file.new to auto-close file ref [\#191](https://github.com/rapid7/nexpose-client/pull/191) ([gschneider-r7](https://github.com/gschneider-r7))

## [v2.1.1](https://github.com/rapid7/nexpose-client/tree/v2.1.1) (2015-10-21)
[Full Changelog](https://github.com/rapid7/nexpose-client/compare/v2.1.0...v2.1.1)

**Merged pull requests:**

- Update URLs for NSC config [\#189](https://github.com/rapid7/nexpose-client/pull/189) ([gschneider-r7](https://github.com/gschneider-r7))

## [v2.1.0](https://github.com/rapid7/nexpose-client/tree/v2.1.0) (2015-10-07)
[Full Changelog](https://github.com/rapid7/nexpose-client/compare/v2.0.2...v2.1.0)

**Fixed bugs:**

- Update Nexpose::Connection\#list\_discovery\_connections for mobile and DHCP [\#165](https://github.com/rapid7/nexpose-client/issues/165)
- SiloProfile Fails when saving new SiloProfile [\#160](https://github.com/rapid7/nexpose-client/issues/160)
- DynamicAssetGroup\#save should raise an error if the result was an error [\#69](https://github.com/rapid7/nexpose-client/issues/69)
- Fixed silo profile creation [\#185](https://github.com/rapid7/nexpose-client/pull/185) ([gschneider-r7](https://github.com/gschneider-r7))
- Refactor, enhance and fix bugs in ScanTemplate [\#183](https://github.com/rapid7/nexpose-client/pull/183) ([jhart-r7](https://github.com/jhart-r7))

**Closed issues:**

- Nexpose [\#186](https://github.com/rapid7/nexpose-client/issues/186)
- Add more engine info and features [\#166](https://github.com/rapid7/nexpose-client/issues/166)
- Get asset count and vuln count for Asset Groups [\#130](https://github.com/rapid7/nexpose-client/issues/130)

**Merged pull requests:**

- Add methods for changing and querying a scan template's ACES logging level [\#187](https://github.com/rapid7/nexpose-client/pull/187) ([tomhart-r7](https://github.com/tomhart-r7))

## [v2.0.2](https://github.com/rapid7/nexpose-client/tree/v2.0.2) (2015-08-13)
[Full Changelog](https://github.com/rapid7/nexpose-client/compare/v2.0.1...v2.0.2)

## [v2.0.1](https://github.com/rapid7/nexpose-client/tree/v2.0.1) (2015-08-07)
[Full Changelog](https://github.com/rapid7/nexpose-client/compare/v2.0.0...v2.0.1)

**Merged pull requests:**

- Txml integration [\#182](https://github.com/rapid7/nexpose-client/pull/182) ([sgreen-r7](https://github.com/sgreen-r7))
- Updated endpoints for txml removals [\#181](https://github.com/rapid7/nexpose-client/pull/181) ([btrujillo-r7](https://github.com/btrujillo-r7))

## [v2.0.0](https://github.com/rapid7/nexpose-client/tree/v2.0.0) (2015-07-16)
[Full Changelog](https://github.com/rapid7/nexpose-client/compare/v1.3.0...v2.0.0)

**Fixed bugs:**

- Site.from\_hash cannot consume data generated by Site.to\_h [\#168](https://github.com/rapid7/nexpose-client/issues/168)
- Problem with Scan Import/Export on Windows [\#120](https://github.com/rapid7/nexpose-client/issues/120)

**Merged pull requests:**

- Password policy expiration [\#180](https://github.com/rapid7/nexpose-client/pull/180) ([dmurray-r7](https://github.com/dmurray-r7))

## [v1.3.0](https://github.com/rapid7/nexpose-client/tree/v1.3.0) (2015-07-07)
[Full Changelog](https://github.com/rapid7/nexpose-client/compare/v1.2.0...v1.3.0)

**Fixed bugs:**

- Asset filter results no longer retrieve site ID [\#178](https://github.com/rapid7/nexpose-client/issues/178)

**Merged pull requests:**

- Update FilteredAsset to support site\_id in Nexpose 5.13 and later [\#179](https://github.com/rapid7/nexpose-client/pull/179) ([gschneider-r7](https://github.com/gschneider-r7))

## [v1.2.0](https://github.com/rapid7/nexpose-client/tree/v1.2.0) (2015-06-24)
[Full Changelog](https://github.com/rapid7/nexpose-client/compare/v1.1.0...v1.2.0)

**Merged pull requests:**

- Add new syslog constants [\#177](https://github.com/rapid7/nexpose-client/pull/177) ([erran-r7](https://github.com/erran-r7))

## [v1.1.0](https://github.com/rapid7/nexpose-client/tree/v1.1.0) (2015-05-29)
[Full Changelog](https://github.com/rapid7/nexpose-client/compare/v1.0.0...v1.1.0)

**Fixed bugs:**

- DiscoveryConnection.save Fails for Existing Connections [\#175](https://github.com/rapid7/nexpose-client/issues/175)

**Closed issues:**

- Create/edit a tag and adding criteria of multiple IP ranges [\#161](https://github.com/rapid7/nexpose-client/issues/161)
- Unable to login to console with Ruby 2.2.1 and nexpose gem version 1.0.0 [\#158](https://github.com/rapid7/nexpose-client/issues/158)
- Update wiki instructions for installing Ruby and the gem [\#132](https://github.com/rapid7/nexpose-client/issues/132)
- Remove dependencies on the rex gem [\#123](https://github.com/rapid7/nexpose-client/issues/123)

**Merged pull requests:**

- Fix discovery connection update [\#176](https://github.com/rapid7/nexpose-client/pull/176) ([erran-r7](https://github.com/erran-r7))
- Omit the "blackouts" field if none were specified [\#174](https://github.com/rapid7/nexpose-client/pull/174) ([erran-r7](https://github.com/erran-r7))
- Set default elevation type for credentials [\#172](https://github.com/rapid7/nexpose-client/pull/172) ([csong-r7](https://github.com/csong-r7))
- Blackouts [\#170](https://github.com/rapid7/nexpose-client/pull/170) ([dmurray-r7](https://github.com/dmurray-r7))
- Lamps/password policy [\#169](https://github.com/rapid7/nexpose-client/pull/169) ([adevitt-r7](https://github.com/adevitt-r7))
- Add DHCP Protocol/Type constants to the DiscoveryConnection class [\#164](https://github.com/rapid7/nexpose-client/pull/164) ([erran-r7](https://github.com/erran-r7))

## [v1.0.0](https://github.com/rapid7/nexpose-client/tree/v1.0.0) (2015-04-08)
[Full Changelog](https://github.com/rapid7/nexpose-client/compare/v0.9.8...v1.0.0)

**Closed issues:**

- Remove 1.9.3 Support [\#95](https://github.com/rapid7/nexpose-client/issues/95)

**Merged pull requests:**

- Merging Staging/v1 into Master [\#157](https://github.com/rapid7/nexpose-client/pull/157) ([sgreen-r7](https://github.com/sgreen-r7))
- Remove Global and Site blackout from gem. [\#155](https://github.com/rapid7/nexpose-client/pull/155) ([kkohli-r7](https://github.com/kkohli-r7))
- Display api error to users for v2.1 if they exist [\#153](https://github.com/rapid7/nexpose-client/pull/153) ([dcastellanos-r7](https://github.com/dcastellanos-r7))
- Fix the failing 2.1 site API fixture issue [\#151](https://github.com/rapid7/nexpose-client/pull/151) ([erran-r7](https://github.com/erran-r7))
- Site api blackouts [\#150](https://github.com/rapid7/nexpose-client/pull/150) ([dmurray-r7](https://github.com/dmurray-r7))
- adhoc\_schedules [\#149](https://github.com/rapid7/nexpose-client/pull/149) ([mhughes-r7](https://github.com/mhughes-r7))
- Merge master into site-api branch [\#146](https://github.com/rapid7/nexpose-client/pull/146) ([abunn-r7](https://github.com/abunn-r7))
- cherry-pick: Send the engine-id when calling DiscoveryConnection\#save [\#145](https://github.com/rapid7/nexpose-client/pull/145) ([erran-r7](https://github.com/erran-r7))
- MOB-149: Add support for mobile powershell and office 365 connections c... [\#144](https://github.com/rapid7/nexpose-client/pull/144) ([rtaylor-r7](https://github.com/rtaylor-r7))
- Send the engine-id when calling DiscoveryConnection\#save [\#143](https://github.com/rapid7/nexpose-client/pull/143) ([erran-r7](https://github.com/erran-r7))
- Update gem to support XML API adding of schedules to adhoc scans [\#142](https://github.com/rapid7/nexpose-client/pull/142) ([mhughes-r7](https://github.com/mhughes-r7))
- API updates for Bi-directional engine features [\#141](https://github.com/rapid7/nexpose-client/pull/141) ([abunn-r7](https://github.com/abunn-r7))
- Wait update [\#139](https://github.com/rapid7/nexpose-client/pull/139) ([sgreen-r7](https://github.com/sgreen-r7))
- site-api/site: collapse include\_asset methods and add deprecrated methods [\#138](https://github.com/rapid7/nexpose-client/pull/138) ([gschneider-r7](https://github.com/gschneider-r7))
- site-api/alert: address some of hound's comments [\#137](https://github.com/rapid7/nexpose-client/pull/137) ([gschneider-r7](https://github.com/gschneider-r7))
- Site api [\#135](https://github.com/rapid7/nexpose-client/pull/135) ([gperez-r7](https://github.com/gperez-r7))

## [v0.9.8](https://github.com/rapid7/nexpose-client/tree/v0.9.8) (2015-03-17)
[Full Changelog](https://github.com/rapid7/nexpose-client/compare/v0.9.7...v0.9.8)

**Merged pull requests:**

- Update Nexpose::ScanTemplate methods for device and service discovery [\#136](https://github.com/rapid7/nexpose-client/pull/136) ([jhart-r7](https://github.com/jhart-r7))
- Remove Ruby 1.9.3 support, require Ruby 2.1.5  [\#134](https://github.com/rapid7/nexpose-client/pull/134) ([gschneider-r7](https://github.com/gschneider-r7))

## [v0.9.7](https://github.com/rapid7/nexpose-client/tree/v0.9.7) (2015-03-17)
[Full Changelog](https://github.com/rapid7/nexpose-client/compare/v0.9.6...v0.9.7)

**Merged pull requests:**

- Allow control of device discovery and other template options [\#133](https://github.com/rapid7/nexpose-client/pull/133) ([jhart-r7](https://github.com/jhart-r7))

## [v0.9.6](https://github.com/rapid7/nexpose-client/tree/v0.9.6) (2015-03-05)
[Full Changelog](https://github.com/rapid7/nexpose-client/compare/v0.9.5...v0.9.6)

**Fixed bugs:**

- have vcr ignore codeclimate as host [\#127](https://github.com/rapid7/nexpose-client/pull/127) ([sgreen-r7](https://github.com/sgreen-r7))

**Closed issues:**

- Allow Users to Indicate Targets with CIDR Notation [\#112](https://github.com/rapid7/nexpose-client/issues/112)
- Add automated testing with Travis-CI or similar [\#108](https://github.com/rapid7/nexpose-client/issues/108)
- Create method to exclude assets from a site config [\#106](https://github.com/rapid7/nexpose-client/issues/106)
- Convert from Net-HTTPS Transport to Rex [\#25](https://github.com/rapid7/nexpose-client/issues/25)

**Merged pull requests:**

- Add API specs via VCR [\#124](https://github.com/rapid7/nexpose-client/pull/124) ([erran-r7](https://github.com/erran-r7))
- Address YARD syntax warnings [\#121](https://github.com/rapid7/nexpose-client/pull/121) ([erran-r7](https://github.com/erran-r7))
- Fix Code Climate test coverage and add local test coverage [\#118](https://github.com/rapid7/nexpose-client/pull/118) ([erran-r7](https://github.com/erran-r7))
- Add .rubocop.yml and .hound.yml [\#116](https://github.com/rapid7/nexpose-client/pull/116) ([erran-r7](https://github.com/erran-r7))
- Add codeclimate-test-reporter as a development dependency [\#114](https://github.com/rapid7/nexpose-client/pull/114) ([erran-r7](https://github.com/erran-r7))
- Badges. More of them. [\#113](https://github.com/rapid7/nexpose-client/pull/113) ([gschneider-r7](https://github.com/gschneider-r7))
- Add specs and .travis.yml [\#111](https://github.com/rapid7/nexpose-client/pull/111) ([erran-r7](https://github.com/erran-r7))
- Exclude assets by IP, hostname, or IP ranges from site [\#109](https://github.com/rapid7/nexpose-client/pull/109) ([gschneider-r7](https://github.com/gschneider-r7))

## [v0.9.5](https://github.com/rapid7/nexpose-client/tree/v0.9.5) (2015-02-09)
[Full Changelog](https://github.com/rapid7/nexpose-client/compare/v0.9.4...v0.9.5)

**Merged pull requests:**

- adding scott green to gemspec as additional author [\#107](https://github.com/rapid7/nexpose-client/pull/107) ([sgreen-r7](https://github.com/sgreen-r7))
- Add gschneider to gem authors [\#105](https://github.com/rapid7/nexpose-client/pull/105) ([gschneider-r7](https://github.com/gschneider-r7))

## [v0.9.4](https://github.com/rapid7/nexpose-client/tree/v0.9.4) (2015-01-28)
[Full Changelog](https://github.com/rapid7/nexpose-client/compare/v0.9.3...v0.9.4)

**Merged pull requests:**

- Merge for Nexpose 5.12 Release [\#104](https://github.com/rapid7/nexpose-client/pull/104) ([mdaines-r7](https://github.com/mdaines-r7))
- fix shared credentials xml element to correctly grab service type [\#102](https://github.com/rapid7/nexpose-client/pull/102) ([sgreen-r7](https://github.com/sgreen-r7))

## [v0.9.3](https://github.com/rapid7/nexpose-client/tree/v0.9.3) (2015-01-05)
[Full Changelog](https://github.com/rapid7/nexpose-client/compare/v0.9.2...v0.9.3)

**Merged pull requests:**

- Ajax clean up [\#101](https://github.com/rapid7/nexpose-client/pull/101) ([mdaines-r7](https://github.com/mdaines-r7))

## [v0.9.2](https://github.com/rapid7/nexpose-client/tree/v0.9.2) (2015-01-05)
[Full Changelog](https://github.com/rapid7/nexpose-client/compare/v0.9.1...v0.9.2)

**Closed issues:**

- Extract Common Credential Module [\#96](https://github.com/rapid7/nexpose-client/issues/96)

## [v0.9.1](https://github.com/rapid7/nexpose-client/tree/v0.9.1) (2015-01-02)
[Full Changelog](https://github.com/rapid7/nexpose-client/compare/v0.9.0...v0.9.1)

## [v0.9.0](https://github.com/rapid7/nexpose-client/tree/v0.9.0) (2014-12-31)
[Full Changelog](https://github.com/rapid7/nexpose-client/compare/v0.8.18...v0.9.0)

**Closed issues:**

- Out of Memory Error on Large Adhoc Report [\#99](https://github.com/rapid7/nexpose-client/issues/99)
- Gem Isn't Using Nokogiri [\#97](https://github.com/rapid7/nexpose-client/issues/97)
- Convert to\_map to to\_h [\#94](https://github.com/rapid7/nexpose-client/issues/94)

**Merged pull requests:**

- Update to the new username attr for xml [\#100](https://github.com/rapid7/nexpose-client/pull/100) ([sgreen-r7](https://github.com/sgreen-r7))
- Refactor/Extract Common Credential Module [\#98](https://github.com/rapid7/nexpose-client/pull/98) ([sgreen-r7](https://github.com/sgreen-r7))

## [v0.8.18](https://github.com/rapid7/nexpose-client/tree/v0.8.18) (2014-12-15)
[Full Changelog](https://github.com/rapid7/nexpose-client/compare/v0.8.17...v0.8.18)

## [v0.8.17](https://github.com/rapid7/nexpose-client/tree/v0.8.17) (2014-12-11)
[Full Changelog](https://github.com/rapid7/nexpose-client/compare/v0.8.16...v0.8.17)

## [v0.8.16](https://github.com/rapid7/nexpose-client/tree/v0.8.16) (2014-12-10)
[Full Changelog](https://github.com/rapid7/nexpose-client/compare/v0.8.15...v0.8.16)

**Merged pull requests:**

- Add incomplete\_assets method [\#93](https://github.com/rapid7/nexpose-client/pull/93) ([gschneider-r7](https://github.com/gschneider-r7))

## [v0.8.15](https://github.com/rapid7/nexpose-client/tree/v0.8.15) (2014-11-12)
[Full Changelog](https://github.com/rapid7/nexpose-client/compare/v0.8.14...v0.8.15)

**Closed issues:**

- Test please ignore [\#92](https://github.com/rapid7/nexpose-client/issues/92)

**Merged pull requests:**

- allow creating vuln exception with site scope [\#91](https://github.com/rapid7/nexpose-client/pull/91) ([gschneider-r7](https://github.com/gschneider-r7))

## [v0.8.14](https://github.com/rapid7/nexpose-client/tree/v0.8.14) (2014-11-11)
[Full Changelog](https://github.com/rapid7/nexpose-client/compare/v0.8.13...v0.8.14)

## [v0.8.13](https://github.com/rapid7/nexpose-client/tree/v0.8.13) (2014-11-05)
[Full Changelog](https://github.com/rapid7/nexpose-client/compare/v0.8.12...v0.8.13)

**Merged pull requests:**

- Expose scan template level control scanning options [\#88](https://github.com/rapid7/nexpose-client/pull/88) ([erran](https://github.com/erran))

## [v0.8.12](https://github.com/rapid7/nexpose-client/tree/v0.8.12) (2014-11-05)
[Full Changelog](https://github.com/rapid7/nexpose-client/compare/v0.8.11...v0.8.12)

**Merged pull requests:**

- Use the \#id reader instead of the nil @id variable [\#90](https://github.com/rapid7/nexpose-client/pull/90) ([erran](https://github.com/erran))
- Use attr\_accessor instead of a custom setter in GlobalSettings [\#89](https://github.com/rapid7/nexpose-client/pull/89) ([erran](https://github.com/erran))

## [v0.8.11](https://github.com/rapid7/nexpose-client/tree/v0.8.11) (2014-11-04)
[Full Changelog](https://github.com/rapid7/nexpose-client/compare/v0.8.10...v0.8.11)

**Merged pull requests:**

- Update Global Settings [\#87](https://github.com/rapid7/nexpose-client/pull/87) ([erran](https://github.com/erran))
- Use bundler for gem tasks [\#86](https://github.com/rapid7/nexpose-client/pull/86) ([erran](https://github.com/erran))

## [v0.8.10](https://github.com/rapid7/nexpose-client/tree/v0.8.10) (2014-10-29)
[Full Changelog](https://github.com/rapid7/nexpose-client/compare/v0.8.9...v0.8.10)

**Closed issues:**

- Site.save on dynamic site causes APIError [\#84](https://github.com/rapid7/nexpose-client/issues/84)

**Merged pull requests:**

- Support mobile dynamic connections [\#85](https://github.com/rapid7/nexpose-client/pull/85) ([rtaylor-r7](https://github.com/rtaylor-r7))

## [v0.8.9](https://github.com/rapid7/nexpose-client/tree/v0.8.9) (2014-10-20)
[Full Changelog](https://github.com/rapid7/nexpose-client/compare/v0.8.8...v0.8.9)

## [v0.8.8](https://github.com/rapid7/nexpose-client/tree/v0.8.8) (2014-10-17)
[Full Changelog](https://github.com/rapid7/nexpose-client/compare/v0.8.7...v0.8.8)

## [v0.8.7](https://github.com/rapid7/nexpose-client/tree/v0.8.7) (2014-10-14)
[Full Changelog](https://github.com/rapid7/nexpose-client/compare/v0.8.6...v0.8.7)

**Closed issues:**

- Error When Loading Dynamic Sites [\#83](https://github.com/rapid7/nexpose-client/issues/83)

## [v0.8.6](https://github.com/rapid7/nexpose-client/tree/v0.8.6) (2014-10-13)
[Full Changelog](https://github.com/rapid7/nexpose-client/compare/v0.8.5...v0.8.6)

**Closed issues:**

- Site.save is not functioning for dynamic sites [\#71](https://github.com/rapid7/nexpose-client/issues/71)

## [v0.8.5](https://github.com/rapid7/nexpose-client/tree/v0.8.5) (2014-10-09)
[Full Changelog](https://github.com/rapid7/nexpose-client/compare/v0.8.1...v0.8.5)

**Closed issues:**

- list\_engines doesn't parse scope attribute [\#76](https://github.com/rapid7/nexpose-client/issues/76)

**Merged pull requests:**

- Add methods to alter scan threads in scan\_template.rb [\#82](https://github.com/rapid7/nexpose-client/pull/82) ([abunn-r7](https://github.com/abunn-r7))
- Fix a bug in silo\_profile xml  [\#81](https://github.com/rapid7/nexpose-client/pull/81) ([gschneider-r7](https://github.com/gschneider-r7))
- include engine scope attribute in list\_engines [\#77](https://github.com/rapid7/nexpose-client/pull/77) ([gschneider-r7](https://github.com/gschneider-r7))
- Removed attributes from from\_json method [\#75](https://github.com/rapid7/nexpose-client/pull/75) ([krankin-r7](https://github.com/krankin-r7))
- fix a typo in dynamic - line 50 [\#73](https://github.com/rapid7/nexpose-client/pull/73) ([vidkun](https://github.com/vidkun))
- Add support for new Description tag in site and group configs [\#70](https://github.com/rapid7/nexpose-client/pull/70) ([gschneider-r7](https://github.com/gschneider-r7))

## [v0.8.1](https://github.com/rapid7/nexpose-client/tree/v0.8.1) (2014-07-03)
[Full Changelog](https://github.com/rapid7/nexpose-client/compare/v0.8.0...v0.8.1)

**Merged pull requests:**

- Add `Criteria\#\<\<\(criterion\)` to stop repetition [\#68](https://github.com/rapid7/nexpose-client/pull/68) ([erran-r7](https://github.com/erran-r7))
- SNMP v3 credential support [\#67](https://github.com/rapid7/nexpose-client/pull/67) ([kprzerwa-r7](https://github.com/kprzerwa-r7))

## [v0.8.0](https://github.com/rapid7/nexpose-client/tree/v0.8.0) (2014-06-13)
[Full Changelog](https://github.com/rapid7/nexpose-client/compare/v0.7.6...v0.8.0)

**Merged pull requests:**

- An incorrect type when parsing JSON in the Asset class for initialization [\#66](https://github.com/rapid7/nexpose-client/pull/66) ([DevinCarr](https://github.com/DevinCarr))

## [v0.7.6](https://github.com/rapid7/nexpose-client/tree/v0.7.6) (2014-06-06)
[Full Changelog](https://github.com/rapid7/nexpose-client/compare/v0.7.5...v0.7.6)

**Merged pull requests:**

- Add methods to scan\_template.rb to enable port exclusion. [\#65](https://github.com/rapid7/nexpose-client/pull/65) ([AdamBunn](https://github.com/AdamBunn))
- Validate and raise error for unsupported colors [\#64](https://github.com/rapid7/nexpose-client/pull/64) ([erran](https://github.com/erran))

## [v0.7.5](https://github.com/rapid7/nexpose-client/tree/v0.7.5) (2014-05-23)
[Full Changelog](https://github.com/rapid7/nexpose-client/compare/v0.7.4...v0.7.5)

**Merged pull requests:**

- Add tag filter to doc [\#63](https://github.com/rapid7/nexpose-client/pull/63) ([zachrab](https://github.com/zachrab))

## [v0.7.4](https://github.com/rapid7/nexpose-client/tree/v0.7.4) (2014-05-07)
[Full Changelog](https://github.com/rapid7/nexpose-client/compare/v0.7.3...v0.7.4)

**Merged pull requests:**

- Fixed escaping in Roles [\#62](https://github.com/rapid7/nexpose-client/pull/62) ([asalazar-r7](https://github.com/asalazar-r7))

## [v0.7.3](https://github.com/rapid7/nexpose-client/tree/v0.7.3) (2014-04-30)
[Full Changelog](https://github.com/rapid7/nexpose-client/compare/v0.7.2...v0.7.3)

**Merged pull requests:**

- Fix updates on Roles. [\#61](https://github.com/rapid7/nexpose-client/pull/61) ([kkohli-r7](https://github.com/kkohli-r7))

## [v0.7.2](https://github.com/rapid7/nexpose-client/tree/v0.7.2) (2014-04-29)
[Full Changelog](https://github.com/rapid7/nexpose-client/compare/v0.7.1...v0.7.2)

**Closed issues:**

- Role constructor does not set id = -1 by default [\#57](https://github.com/rapid7/nexpose-client/issues/57)

**Merged pull requests:**

- Set role.id to -1 by default on initialization [\#60](https://github.com/rapid7/nexpose-client/pull/60) ([erran](https://github.com/erran))
- Add controls-insight-only as a valid role [\#58](https://github.com/rapid7/nexpose-client/pull/58) ([erran](https://github.com/erran))

## [v0.7.1](https://github.com/rapid7/nexpose-client/tree/v0.7.1) (2014-04-10)
[Full Changelog](https://github.com/rapid7/nexpose-client/compare/v0.7.0...v0.7.1)

## [v0.7.0](https://github.com/rapid7/nexpose-client/tree/v0.7.0) (2014-03-26)
[Full Changelog](https://github.com/rapid7/nexpose-client/compare/v0.6.5...v0.7.0)

**Closed issues:**

- Implement Missing Silo Calls [\#21](https://github.com/rapid7/nexpose-client/issues/21)
- Implement PendingVulnExceptionsCountRequest Call [\#18](https://github.com/rapid7/nexpose-client/issues/18)
- Implement Missing MultiTenant Calls [\#17](https://github.com/rapid7/nexpose-client/issues/17)
- Discovery Connection Calls [\#15](https://github.com/rapid7/nexpose-client/issues/15)

**Merged pull requests:**

- Changes for criticality tags and associated assets [\#56](https://github.com/rapid7/nexpose-client/pull/56) ([zachrab](https://github.com/zachrab))
- Ivan - Support for tags [\#55](https://github.com/rapid7/nexpose-client/pull/55) ([kkohli-r7](https://github.com/kkohli-r7))
- Minor licensing and naming updates [\#54](https://github.com/rapid7/nexpose-client/pull/54) ([todb-r7](https://github.com/todb-r7))
- Updating Silo functionality in the Gem [\#52](https://github.com/rapid7/nexpose-client/pull/52) ([asalazar-r7](https://github.com/asalazar-r7))

## [v0.6.5](https://github.com/rapid7/nexpose-client/tree/v0.6.5) (2014-03-11)
[Full Changelog](https://github.com/rapid7/nexpose-client/compare/v0.6.4...v0.6.5)

**Closed issues:**

- Site class missing organization attributes [\#53](https://github.com/rapid7/nexpose-client/issues/53)

## [v0.6.4](https://github.com/rapid7/nexpose-client/tree/v0.6.4) (2014-03-10)
[Full Changelog](https://github.com/rapid7/nexpose-client/compare/v0.6.3...v0.6.4)

**Merged pull requests:**

- Fix for dynamic asset group creation [\#51](https://github.com/rapid7/nexpose-client/pull/51) ([zachrab](https://github.com/zachrab))

## [v0.6.3](https://github.com/rapid7/nexpose-client/tree/v0.6.3) (2014-02-25)
[Full Changelog](https://github.com/rapid7/nexpose-client/compare/v0.6.2...v0.6.3)

**Closed issues:**

- VulnException save\(\) drops comment when sending request [\#50](https://github.com/rapid7/nexpose-client/issues/50)
- Site save doesn't sanitize description for XML entities [\#49](https://github.com/rapid7/nexpose-client/issues/49)
- Nexpose::ReportConfig.build incorrectly adds frequency when generate\_now is true [\#43](https://github.com/rapid7/nexpose-client/issues/43)

## [v0.6.2](https://github.com/rapid7/nexpose-client/tree/v0.6.2) (2014-01-30)
[Full Changelog](https://github.com/rapid7/nexpose-client/compare/v0.6.1...v0.6.2)

**Closed issues:**

- rescan\_assets does not work in 0.6.1 [\#48](https://github.com/rapid7/nexpose-client/issues/48)
- Filter constant EARLIER\_THAN is missing [\#47](https://github.com/rapid7/nexpose-client/issues/47)
- ScanTemplate.copy does not work in 0.6.1 [\#46](https://github.com/rapid7/nexpose-client/issues/46)
- After a successful authentication, session\_id is nil since gem version 0.1.3 [\#45](https://github.com/rapid7/nexpose-client/issues/45)

## [v0.6.1](https://github.com/rapid7/nexpose-client/tree/v0.6.1) (2014-01-09)
[Full Changelog](https://github.com/rapid7/nexpose-client/compare/v0.6.0...v0.6.1)

## [v0.6.0](https://github.com/rapid7/nexpose-client/tree/v0.6.0) (2013-12-18)
[Full Changelog](https://github.com/rapid7/nexpose-client/compare/v0.5.6...v0.6.0)

**Merged pull requests:**

- Added equality comparison to report filters and modified single quote XM... [\#42](https://github.com/rapid7/nexpose-client/pull/42) ([zeroorone13](https://github.com/zeroorone13))

## [v0.5.6](https://github.com/rapid7/nexpose-client/tree/v0.5.6) (2013-11-21)
[Full Changelog](https://github.com/rapid7/nexpose-client/compare/v0.5.5...v0.5.6)

## [v0.5.5](https://github.com/rapid7/nexpose-client/tree/v0.5.5) (2013-11-08)
[Full Changelog](https://github.com/rapid7/nexpose-client/compare/v0.5.4...v0.5.5)

**Closed issues:**

- Create an executable for useful tasks [\#40](https://github.com/rapid7/nexpose-client/issues/40)

**Merged pull requests:**

- Fixed call to delete\_device \(method name changed\) [\#41](https://github.com/rapid7/nexpose-client/pull/41) ([pdogg](https://github.com/pdogg))

## [v0.5.4](https://github.com/rapid7/nexpose-client/tree/v0.5.4) (2013-09-27)
[Full Changelog](https://github.com/rapid7/nexpose-client/compare/v0.5.3...v0.5.4)

## [v0.5.3](https://github.com/rapid7/nexpose-client/tree/v0.5.3) (2013-09-27)
[Full Changelog](https://github.com/rapid7/nexpose-client/compare/v0.5.2...v0.5.3)

**Closed issues:**

- Move NexpoesAPI into a new Nexpose::API module [\#39](https://github.com/rapid7/nexpose-client/issues/39)

## [v0.5.2](https://github.com/rapid7/nexpose-client/tree/v0.5.2) (2013-09-17)
[Full Changelog](https://github.com/rapid7/nexpose-client/compare/v0.5.1...v0.5.2)

**Closed issues:**

- Examples for running scans etc. [\#37](https://github.com/rapid7/nexpose-client/issues/37)
- Clean up Comments - Switch to YARDoc [\#24](https://github.com/rapid7/nexpose-client/issues/24)
- Make the Wiki Helpful [\#23](https://github.com/rapid7/nexpose-client/issues/23)
- Nexpose::ReportAdHoc strange behavior with different formats [\#4](https://github.com/rapid7/nexpose-client/issues/4)

## [v0.5.1](https://github.com/rapid7/nexpose-client/tree/v0.5.1) (2013-09-15)
[Full Changelog](https://github.com/rapid7/nexpose-client/compare/v0.5.0...v0.5.1)

**Merged pull requests:**

- Allow for Nexpose::Connection.new to consume URI objects [\#38](https://github.com/rapid7/nexpose-client/pull/38) ([erran](https://github.com/erran))

## [v0.5.0](https://github.com/rapid7/nexpose-client/tree/v0.5.0) (2013-09-01)
**Closed issues:**

- ReportTemplate delete does not work [\#36](https://github.com/rapid7/nexpose-client/issues/36)
- Request for site\_device\_search\_by\_address in site.rb [\#35](https://github.com/rapid7/nexpose-client/issues/35)
- bug in regex in vuln.rb:461 [\#34](https://github.com/rapid7/nexpose-client/issues/34)
- create\_ticket casing for vuln\_id [\#33](https://github.com/rapid7/nexpose-client/issues/33)
- Alerts Are Not Correctly Parsed or Saved [\#32](https://github.com/rapid7/nexpose-client/issues/32)
- Gem version 0.1.8 doesn't work with Ruby 1.8.7 [\#28](https://github.com/rapid7/nexpose-client/issues/28)
- Implement Missing Ticketing Calls [\#22](https://github.com/rapid7/nexpose-client/issues/22)
- Implement ScanListingRequest [\#20](https://github.com/rapid7/nexpose-client/issues/20)
- Implement Role API Calls [\#19](https://github.com/rapid7/nexpose-client/issues/19)
- Implement EngineActivityRequest Call [\#16](https://github.com/rapid7/nexpose-client/issues/16)
- Saving of Asset Groups [\#14](https://github.com/rapid7/nexpose-client/issues/14)
- site\_device\_listing not returning risk scores [\#11](https://github.com/rapid7/nexpose-client/issues/11)
- site\_device\_listing not returning risk scores [\#10](https://github.com/rapid7/nexpose-client/issues/10)
- hostnames not included in site\_config [\#8](https://github.com/rapid7/nexpose-client/issues/8)
- Nexpose changed answer format since yesterday? [\#6](https://github.com/rapid7/nexpose-client/issues/6)
- undefined local variable or method `response' [\#2](https://github.com/rapid7/nexpose-client/issues/2)
- No Method geturl in nexpose.rb:2536 [\#1](https://github.com/rapid7/nexpose-client/issues/1)

**Merged pull requests:**

- resolved missing highline/import [\#30](https://github.com/rapid7/nexpose-client/pull/30) ([vidkun](https://github.com/vidkun))
- Add host set ability for complete array [\#26](https://github.com/rapid7/nexpose-client/pull/26) ([arirubinstein](https://github.com/arirubinstein))
- Bug fix for scan\_pause and scan\_resume [\#13](https://github.com/rapid7/nexpose-client/pull/13) ([mickayz](https://github.com/mickayz))
- Added scan\_pause method to scan.rb [\#12](https://github.com/rapid7/nexpose-client/pull/12) ([mickayz](https://github.com/mickayz))



\* *This Change Log was automatically generated by [github_changelog_generator](https://github.com/skywinder/Github-Changelog-Generator)*