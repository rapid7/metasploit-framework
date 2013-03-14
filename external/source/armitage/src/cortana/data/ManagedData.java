package cortana.data;

import cortana.core.*;

import armitage.ArmitageTimerClient;
import armitage.ArmitageTimer;

import graph.Route;

import sleep.bridges.*;
import sleep.interfaces.*;
import sleep.runtime.*;
import sleep.engine.*;

import java.util.*;

import java.io.IOException;

import msf.*;

public abstract class ManagedData {
	protected boolean        initial = true;
	protected Scalar         cache   = null;

	public boolean isInitial() {
		return initial;
	}

	public abstract Scalar getScalar();

	public void reset() {
		initial = true;
	}
}
