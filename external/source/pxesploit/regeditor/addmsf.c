
#include <sys/types.h>
#include "ntreg.h"
int main(){
	struct hive *myhive;
	myhive = openHive("SYSTEM", HMODE_RW);
	if(myhive == 0)
		myhive = openHive("system", HMODE_RW);
	if(myhive == 0)
		myhive = openHive("System", HMODE_RW);
	put_dword(myhive, 0, "ControlSet001\\Services\\Spooler\\Start", TPF_VK_EXACT, 2);
	put_dword(myhive, 0, "ControlSet002\\Services\\Spooler\\Start", TPF_VK_EXACT, 2);
	writeHive(myhive);
	closeHive(myhive);
}

