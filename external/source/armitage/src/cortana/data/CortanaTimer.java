package cortana.data;

import armitage.*;
import msf.*;

public class CortanaTimer extends ArmitageTimer {
	protected DataManager clientz;

	protected boolean alwaysFire() {
		return !clientz.isReady();
	}

	public CortanaTimer(RpcConnection connection, String command, long sleepPeriod, DataManager client, boolean doCache) {
		super(connection, command, sleepPeriod, client, doCache);
		this.clientz = client;
	}
}
