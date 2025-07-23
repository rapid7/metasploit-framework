#!/bin/sh -ex
bundle install
rm -f db/modules_metadata_base.json
git ls-files modules/ -z | xargs -0 -n1 -P `nproc` -I{} -- git log -1 --format="%ai {}" {} | while read -r udate utime utz ufile ; do
  touch -d "$udate $utime" $ufile
done
./msfconsole --no-defer-module-loads -qr tools/automation/cache/wait_for_cache.rc
cp ~/.msf4/store/modules_metadata.json db/modules_metadata_base.json
cp ~/.msf4/logs/framework.log .
set +e
git diff --exit-code db/modules_metadata_base.json
if [ ! $? ]; then
  echo "Module cache updates exist."
fi
