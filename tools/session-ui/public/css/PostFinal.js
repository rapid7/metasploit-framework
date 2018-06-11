<!DOCTYPE html>
<html>
<body>

<p>How to access nested JSON objects.</p>

<ul>
<li>Post Exploitation Modules
<ul id="post">

</ul>
</li>
</ul>
<p id="post1"></p>
<script>
var myObj = {
	"aix" 	  : ["dhawan"],
	"android" : {"capture" :"screen",
				 "gather" : "wireless",
				 "manage"	: ["remove_lock","remove_lock_root"]
				},

	"cisco" : {"gather" : "enum_cisco"},

	"firefox" : {"gather" : ["cookies","history","password","xss"],
				 "manage" : "webcam_chat"	
				},
	"hardware" : {"automotive" : ["canprobe","getvinfo","identifymodules","malibu_overheat","pdt"],
				  "rftransciever" : ["rftwnon","transmitter"],
				  "Zigbee" : "zstumber"
				  },
	"juniper" : {"gather" : "enum_juniper"},

	"linux" : {"busybox" : ["enum_connection","enum_hosts","jailbreak","ping_net","set_dns","smb_share_root","wget_exec"],
			   "dos" : "xen_420_dos",
			   "gather" : ["Check_container","checkvm","encrypt_creed","enum_configs","enum_network","enum_protection","enum_psk","enum_system","enum_xchat","etc...etc"],
			   "manage" : ["download_exec","sshkey_persistence"]
			   },

	"multi" : { "escalate" : ["aes_create_iam_user","cups_root_file_read","metasploit_pcaplog"]	,
				"gather"   : ["apple_ios_backup","aws_ec2_instance_metadataaws_keys", "check_malware",
								"dbvis_enum", "dns_bruteforce", "env", "fetchmailrc_creds", "filezilla_client_cred", 
								"find_vmx", "jboss_gather" ,"firefox_creds", "irssi_creds" 
							]	,
				"general"  : ["close","execute","wall"]	,
				"manage"   : ["autoroute","sudo","zip","system_session","set_wallpaper","play_youtube",
							  "unload_exec","record_mic","etc..etc"
							],
				"recon"	   : ["local_exploit_suggester","multi_egress_traffic"]	
				},
	"osx" : { "admin" : "say",
			  "capture" : ["keylog_recorder","screen"],
			  "gather" : ["enum_osx","hashdump","password_spoof_prompt","safari_lastsession","enum_messages","enum_adium","enum_airport","autologin_password"
			  			 ],
			  "manage" : ["mount_share","record_mic","vpn","webcam"]


			},
	"solaris" : {"gather" : ["checkvm","enum_package","enum_services","hashdump"]
				},
	"windows" : {
					"capture"  : [ "keylog_record","lockout_keylogger"],

					"escalate" : [ "droplnk","getsystem","golden_ticket","ms10_073","screen_unclock"],

					"gather" :  ["ad_to_sqlite","checkvm","dumplink","enum_db","cachedump","enum_devices"],

					"manage" :	["killav","hash","delete_user","enable_rdp","pptp_tunnel","driver_loader","portproxy"],				 

					"recon" :	["computer_browser_history","outbound_ports","resolve_ip"],
					
					"wlan" :	["wlan_bss_list","wlan_current_connection","wlan_disconnect","wlan_probe_request","wlan_profile"]
				}				
}
//document.getElementById("demo").innerHTML += myObj.cars.car2 + "<br>";
//or:
//var mydata=JSON.parse(myObj);
var arr= Object.keys(myObj);// windwos,cisco,linux,OSX

for(var i=0;i<arr.length;i++)
{
	
	var text=document.createElement("li");
    var myList = document.createElement('ul');
    
    text.textContent=arr[i];
    
    var post_mod =myObj[arr[i]]; 		// content inside windows,linux
    //keys of content
   //console.log(post_mod)
    var postmod_key=Object.keys(post_mod);
    var postmod_val=Object.values(post_mod);
   console.log(postmod_val);
     
    if(postmod_key[i]!=0){
    	for(var j=0;j< postmod_key.length;j++){
   			 var subList=document.createElement('li');
             subList.textContent=postmod_key[j];
             myList.appendChild(subList);
             
             if(postmod_val!=0){
             	for(var k=0;k<postmod_val.length;k++){
             		var valueSubList=document.createElement("ul");
                	var valueList=document.createElement("li");
                	valueList.textContent=postmod_val[k];
                	valueSubList.appendChild(valueList);
                	subList.appendChild(valueSubList);
             		myList.appendChild(subList);
             	}
             }
   		}
   } 
   	
   
    text.appendChild(myList);
    document.getElementById("post").appendChild(text);
}

</script>

</body>
</html>
