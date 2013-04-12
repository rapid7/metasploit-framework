#!/bin/bash

cd ..
mvn package -P deploy
cd -

echo 'Building shell'
dx --verbose --dex \
    --output=../../../../data/android/shell.jar \
    library/target/classes/./androidpayload/stage/Shell.class library/target/classes/./androidpayload/stage/Stage.class \
    ../javapayload/target/classes/./javapayload/stage/StreamForwarder.class

echo 'Building meterpreter stage'
dx --verbose --dex \
    --output=../../../../data/android/metstage.jar \
    library/target/classes/./androidpayload/stage/Meterpreter.class library/target/classes/./androidpayload/stage/Stage.class 

echo 'Building meterpreter'
dx --verbose --dex \
    --output=../../../../data/android/meterpreter.jar \
    library/target/classes/./com/metasploit/meterpreter/android/*.class \
    library/target/classes/./com/metasploit/meterpreter/*.class \
    ../meterpreter/meterpreter/target/meterpreter.jar \
    ../meterpreter/stdapi/target/ext_server_stdapi.jar

