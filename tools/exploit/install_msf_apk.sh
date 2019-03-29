#!/usr/bin/env bash

# This script allows you install your msf payload apk to your Android emulator.
# Make sure you have Java and Android SDK.

apk_path=$1


if ! [ -x "$(command -v adb)" ]
then
  echo "Android SDK platform-tools not included in \$PATH."
  exit
fi

if ! [ -x "$(command -v jarsigner)" ]
then
  echo "jarsigner is missing."
  exit
fi

if ! [ -e "$HOME/.android/debug.keystore" ]
then
  echo "Missing ~/.android/debug.keystore"
  exit
fi

if [ -z "$apk_path" ]
then
  echo "APK path is required."
  exit
fi

if ! [ -a "$apk_path" ]
then
  echo "APK not found."
  exit
fi

jarsigner -verbose -keystore ~/.android/debug.keystore -storepass android -keypass android -digestalg SHA1 -sigalg MD5withRSA $apk_path androiddebugkey
adb uninstall com.metasploit.stage
adb install -r $apk_path
adb shell am start -a android.intent.action.MAIN -n com.metasploit.stage/.MainActivity