#!/bin/sh

dst_folder="../../../"
for file in $(find ./ -name "*.s")
do
   arch=`echo $file | cut -d "_" -f2`;
   nasm -f bin $file -o $dst_folder"template_"$arch"_linux.bin"
 done
