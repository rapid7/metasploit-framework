package msf;

import java.util.*;
import java.sql.*;

import java.io.*;

import graph.Route;

/* implement the old MSF RPC database calls in a way Armitage likes */
public class DatabaseImpl implements RpcConnection  {
	protected Connection db;
	protected Map queries;
	protected String workspaceid = "0";
	protected String hFilter = null;
	protected String sFilter = null;
	protected String[] lFilter = null;
	protected Route[]  rFilter = null;
	protected String[] oFilter = null;
	protected int hindex = 0;
	protected int sindex = 0;

	/* keep track of labels associated with each host */
	protected Map labels = new HashMap();

	/* define the maximum hosts in a workspace */
	protected int maxhosts = 512;

	/* define the maximum services in a workspace */
	protected int maxservices = 512 * 24;

	public void resetHostsIndex() {
		hindex = 0;
		queries = build();
	}

	public void resetServicesIndex() {
		sindex = 0;
		queries = build();
	}

	public void nextHostsIndex() {
		hindex += 1;
		queries = build();
	}

	public void nextServicesIndex() {
		sindex += 1;
		queries = build();
	}

	private static String join(List items, String delim) {
		StringBuffer result = new StringBuffer();
		Iterator i = items.iterator();
		while (i.hasNext()) {
			result.append(i.next());
			if (i.hasNext()) {
				result.append(delim);
			}
		}
		return result.toString();
	}

	public void setWorkspace(String name) {
		try {
			List spaces = executeQuery("SELECT DISTINCT * FROM workspaces");
			Iterator i = spaces.iterator();
			while (i.hasNext()) {
				Map temp = (Map)i.next();
				if (name.equals(temp.get("name"))) {
					workspaceid = temp.get("id") + "";
					queries = build();
				}
			}
		}
		catch (Exception ex) {
			throw new RuntimeException(ex);
		}
	}

	public void setDebug(boolean d) {

	}

	public DatabaseImpl() {
		queries = build();
	}

	private static long tzfix = 0;

	static {
		Calendar now = Calendar.getInstance();
		tzfix = now.get(Calendar.ZONE_OFFSET) + now.get(Calendar.DST_OFFSET);
	}

	/* marshall the type into something we'd rather deal with */
	protected Object fixResult(Object o) {
		if (o instanceof java.sql.Timestamp) {
			return new Long( ((Timestamp)o).getTime() + tzfix );
		}
		else if (o instanceof org.postgresql.util.PGobject) {
			return o.toString();
		}
		return o;
	}

	protected int executeUpdate(String query) throws Exception {
		Statement s = db.createStatement();
		return s.executeUpdate(query);
	}

	/* execute the query and return a linked list of the results..., whee?!? */
	protected List executeQuery(String query) throws Exception {
		List results = new LinkedList();

		Statement s = db.createStatement();
		ResultSet r = s.executeQuery(query);

		while (r.next()) {
			Map row = new HashMap();

			ResultSetMetaData m = r.getMetaData();
			int c = m.getColumnCount();
			for (int i = 1; i <= c; i++) {
				row.put(m.getColumnLabel(i), fixResult(r.getObject(i)));
			}

			results.add(row);
		}

		return results;
	}

	private boolean checkRoute(String address) {
		for (int x = 0; x < rFilter.length; x++) {
			if (rFilter[x].shouldRoute(address))
				return true;
		}
		return false;
	}

	private boolean checkLabel(String host) {
		if (!labels.containsKey(host))
			return false;

		String label_l = (labels.get(host) + "").toLowerCase();

		for (int x = 0; x < lFilter.length; x++) {
			if (label_l.indexOf(lFilter[x]) != -1) {
				return true;
			}
		}
		return false;
	}

	private boolean checkOS(String os) {
		String os_l = os.toLowerCase();

		for (int x = 0; x < oFilter.length; x++) {
			if (os_l.indexOf(oFilter[x]) != -1)
				return true;
		}
		return false;
	}

	protected void loadLabels() {
		try {
			/* query database for label data */
			List rows = executeQuery("SELECT DISTINCT data FROM notes WHERE ntype = 'armitage.labels'");
			if (rows.size() == 0)
				return;

			/* extract our BASE64 encoded data */
			String data = ((Map)rows.get(0)).get("data") + "";
			System.err.println("Read: " + data.length() + " bytes");

			/* turn our data into raw data */
			byte[] raw  = Base64.decode(data);

			/* deserialize our notes data */
			ByteArrayInputStream store = new ByteArrayInputStream(raw);
			ObjectInputStream handle = new ObjectInputStream(store);
			Map temp = (Map)(handle.readObject());
			handle.close();
			store.close();

			/* merge with our new map */
			labels.putAll(temp);
		}
		catch (Exception ex) {
			ex.printStackTrace();
		}
	}

	protected void mergeLabels(Map l) {
		/* accept any label values and merge them into our global data set */
		Iterator i = l.entrySet().iterator();
		while (i.hasNext()) {
			Map.Entry entry = (Map.Entry)i.next();
			if ("".equals(entry.getValue())) {
				labels.remove(entry.getKey() + "");
			}
			else {
				labels.put(entry.getKey() + "", entry.getValue() + "");
			}
		}
	}

	/* add labels to our hosts */
	public List addLabels(List rows) {
		if (labels.size() == 0)
			return rows;

		Iterator i = rows.iterator();
		while (i.hasNext()) {
			Map entry = (Map)i.next();
			String address = (entry.containsKey("address") ? entry.get("address") : entry.get("host")) + "";
			if (labels.containsKey(address)) {
				entry.put("label", labels.get(address) + "");
			}
			else {
				entry.put("label", "");
			}
		}

		return rows;
	}

	public List filterByRoute(List rows, int max) {
		if (rFilter != null || oFilter != null || lFilter != null) {
			Iterator i = rows.iterator();
			while (i.hasNext()) {
				Map entry = (Map)i.next();

				/* make sure the address is within a route we care about */
				if (rFilter != null && entry.containsKey("address")) {
					if (!checkRoute(entry.get("address") + "")) {
						i.remove();
						continue;
					}
				}
				else if (rFilter != null && entry.containsKey("host")) {
					if (!checkRoute(entry.get("host") + "")) {
						i.remove();
						continue;
					}
				}

				/* make sure the host is something we care about too */
				if (oFilter != null && entry.containsKey("os_name")) {
					if (!checkOS(entry.get("os_name") + "")) {
						i.remove();
						continue;
					}
				}

				/* make sure the host has the right label */
				if (lFilter != null && entry.containsKey("address")) {
					if (!checkLabel(entry.get("address") + "")) {
						i.remove();
						continue;
					}
				}
				else if (lFilter != null && entry.containsKey("host")) {
					if (!checkLabel(entry.get("host") + "")) {
						i.remove();
						continue;
					}
				}
			}

			if (rows.size() > max) {
				rows.subList(max, rows.size()).clear();
			}
		}

		return rows;
	}

	public void connect(String dbstring, String user, String password) throws Exception {
		db = DriverManager.getConnection(dbstring, user, password);
		setWorkspace("default");
		loadLabels();
	}

	public Object execute(String methodName) throws IOException {
		return execute(methodName, new Object[0]);
	}

	protected Map build() {
		Map temp = new HashMap();

		/* this is an optimization. If we have a network or OS filter, we need to pull back all host/service records and
		   filter them here. If we do not have these types of filters, then we can let the database do the heavy lifting
		   and limit the size of the final result there. */
		int limit1 = rFilter == null && oFilter == null && lFilter == null ? maxhosts : 30000;
		int limit2 = rFilter == null && oFilter == null && lFilter == null ? maxservices : 100000;

		temp.put("db.creds", "SELECT DISTINCT creds.*, hosts.address as host, services.name as sname, services.port as port, services.proto as proto FROM creds, services, hosts WHERE services.id = creds.service_id AND hosts.id = services.host_id AND hosts.workspace_id = " + workspaceid);

		/* db.creds2 exists to prevent duplicate entries for the stuff I care about */
		temp.put("db.creds2", "SELECT DISTINCT creds.user, creds.pass, hosts.address as host, services.name as sname, services.port as port, services.proto as proto, creds.ptype FROM creds, services, hosts WHERE services.id = creds.service_id AND hosts.id = services.host_id AND hosts.workspace_id = " + workspaceid);

		if (hFilter != null) {
			List tables = new LinkedList();
			tables.add("hosts");
			if (hFilter.indexOf("services.") >= 0)
				tables.add("services");

			if (hFilter.indexOf("sessions.") >= 0)
				tables.add("sessions");

			temp.put("db.hosts", "SELECT DISTINCT hosts.id, hosts.updated_at, hosts.state, hosts.mac, hosts.purpose, hosts.os_flavor, hosts.os_name, hosts.address, hosts.os_sp FROM " + join(tables, ", ") + " WHERE hosts.workspace_id = " + workspaceid + " AND " + hFilter + " ORDER BY hosts.id ASC LIMIT " + limit1 + " OFFSET " + (limit1 * hindex));
		}
		else {
			temp.put("db.hosts", "SELECT DISTINCT hosts.id, hosts.updated_at, hosts.state, hosts.mac, hosts.purpose, hosts.os_flavor, hosts.os_name, hosts.address, hosts.os_sp FROM hosts WHERE hosts.workspace_id = " + workspaceid + " ORDER BY hosts.id ASC LIMIT " + limit1 + " OFFSET " + (hindex * limit1));
		}

		temp.put("db.services", "SELECT DISTINCT services.id, services.name, services.port, services.proto, services.info, services.updated_at, hosts.address as host FROM services, (" + temp.get("db.hosts") + ") as hosts WHERE hosts.id = services.host_id AND services.state = 'open' ORDER BY services.id ASC LIMIT " + limit2 + " OFFSET " + (limit2 * sindex));
		temp.put("db.loots", "SELECT DISTINCT loots.*, hosts.address as host FROM loots, hosts WHERE hosts.id = loots.host_id AND hosts.workspace_id = " + workspaceid);
		temp.put("db.workspaces", "SELECT DISTINCT * FROM workspaces");
		temp.put("db.notes", "SELECT DISTINCT notes.*, hosts.address as host FROM notes, hosts WHERE hosts.id = notes.host_id AND hosts.workspace_id = " + workspaceid);
		temp.put("db.clients", "SELECT DISTINCT clients.*, hosts.address as host FROM clients, hosts WHERE hosts.id = clients.host_id AND hosts.workspace_id = " + workspaceid);
		temp.put("db.sessions", "SELECT DISTINCT sessions.*, hosts.address as host FROM sessions, hosts WHERE hosts.id = sessions.host_id AND hosts.workspace_id = " + workspaceid);
		temp.put("db.events", "SELECT DISTINCT id, username, info, created_at FROM events WHERE events.name = 'armitage.event' ORDER BY id ASC");
		return temp;
	}

	public Object execute(String methodName, Object[] params) throws IOException {
		try {
			if (queries.containsKey(methodName)) {
				String query = queries.get(methodName) + "";
				Map result = new HashMap();

				if (methodName.equals("db.services")) {
					result.put(methodName.substring(3), filterByRoute(executeQuery(query), maxservices));
				}
				else if (methodName.equals("db.hosts")) {
					result.put(methodName.substring(3), addLabels(filterByRoute(executeQuery(query), maxhosts)));
				}
				else {
					result.put(methodName.substring(3), executeQuery(query));
				}
				return result;
			}
			else if (methodName.equals("db.vulns")) {
				//List a = executeQuery("SELECT DISTINCT vulns.*, hosts.address as host, services.port as port, services.proto as proto FROM vulns, hosts, services WHERE hosts.id = vulns.host_id AND services.id = vulns.service_id");
				//List b = executeQuery("SELECT DISTINCT vulns.*, hosts.address as host FROM vulns, hosts WHERE hosts.id = vulns.host_id AND vulns.service_id IS NULL");
				List a = executeQuery("SELECT DISTINCT vulns.*, vulns.id as vid, hosts.address as host, services.port as port, services.proto as proto, refs.name as refs FROM vulns, hosts, services, vulns_refs, refs WHERE hosts.id = vulns.host_id AND services.id = vulns.service_id AND vulns_refs.vuln_id = vulns.id AND vulns_refs.ref_id = refs.id AND hosts.workspace_id = " + workspaceid);
				List b = executeQuery("SELECT DISTINCT vulns.*, vulns.id as vid, hosts.address as host, refs.name as refs FROM vulns, hosts, refs, vulns_refs WHERE hosts.id = vulns.host_id AND vulns.service_id IS NULL AND vulns_refs.vuln_id = vulns.id AND vulns_refs.ref_id = refs.id AND hosts.workspace_id = " + workspaceid);

				a.addAll(b);

				Map result = new HashMap();
				result.put("vulns", a);
				return result;
			}
			else if (methodName.equals("db.log_event")) {
				PreparedStatement stmt = null;
				stmt = db.prepareStatement("INSERT INTO events (name, username, info, created_at) VALUES ('armitage.event', ?, ?, now() AT TIME ZONE 'GMT')");
				stmt.setString(1, params[0] + "");
				stmt.setString(2, params[1] + "");
				stmt.executeUpdate();
				return new HashMap();
			}
			else if (methodName.equals("db.key_add")) {
				PreparedStatement stmt = null;
				stmt = db.prepareStatement("INSERT INTO notes (ntype, data) VALUES (?, ?)");
				stmt.setString(1, params[0] + "");
				stmt.setString(2, params[1] + "");
				stmt.executeUpdate();
				return new HashMap();
			}
			else if (methodName.equals("db.key_delete")) {
				PreparedStatement stmt = null;
				stmt = db.prepareStatement("DELETE FROM notes WHERE id = ?");
				stmt.setString(1, params[0] + "");
				stmt.executeUpdate();
				return new HashMap();
			}
			else if (methodName.equals("db.key_clear")) {
				PreparedStatement stmt = null;
				stmt = db.prepareStatement("DELETE FROM notes WHERE ntype = ?");
				stmt.setString(1, params[0] + "");
				stmt.executeUpdate();
				return new HashMap();
			}
			else if (methodName.equals("db.key_values")) {
				Map results = new HashMap();
				String key = params[0] + "";
				if (!key.matches("[0-9a-zA-Z\\._]+")) {
					System.err.println("Key '" + key + "' did not validate!");
					return new HashMap();
				}
				results.put("values", executeQuery("SELECT DISTINCT * FROM notes WHERE ntype = '" + key + "' ORDER BY id ASC"));
				return results;
			}
			else if (methodName.equals("db.clear_cache")) {
				/* force a clear of the module cache */
				executeUpdate(
					"BEGIN;" +
					"DELETE FROM module_details;" +
					"DELETE FROM module_details;" +
					"DELETE FROM module_targets;" +
					"DELETE FROM module_authors;" +
					"DELETE FROM module_actions;" +
					"DELETE FROM module_mixins;" +
					"DELETE FROM module_platforms;" +
					"DELETE FROM module_archs;" +
					"DELETE FROM module_refs;" +
					"COMMIT");
				return new HashMap();
			}
			else if (methodName.equals("db.clear")) {
				/* clear our local cache of labels */
				labels = new HashMap();

				/* clear the database */
				executeUpdate(
					"BEGIN;" +
					"DELETE FROM hosts;" +
					"DELETE FROM services;" +
					"DELETE FROM events;" +
					"DELETE FROM notes;" +
					"DELETE FROM creds;" +
					"DELETE FROM loots;" +
					"DELETE FROM vulns;" +
					"DELETE FROM sessions;" +
					"DELETE FROM clients;" +
					"COMMIT");
				return new HashMap();
			}
			else if (methodName.equals("db.filter")) {
				/* I'd totally do parameterized queries if I wasn't building this
				   damned query dynamically. Hence it'll have to do. */
				Map values = (Map)params[0];

				rFilter = null;
				oFilter = null;
				lFilter = null;

				List hosts = new LinkedList();
				List srvcs = new LinkedList();

				if ((values.get("session") + "").equals("1")) {
					hosts.add("sessions.host_id = hosts.id AND sessions.closed_at IS NULL AND sessions.close_reason IS NULL");
					//srvcs.add("sessions.host_id = hosts.id AND sessions.closed_at IS NULL");
				}

				if (values.containsKey("size")) {
					try {
						maxhosts = Integer.parseInt(values.get("size") + "");
						maxservices = maxhosts * 24;
					}
					catch (Exception ex) {
					}
				}

				if (values.containsKey("hosts") && (values.get("hosts") + "").length() > 0) {
					String h = values.get("hosts") + "";
					if (!h.matches("[0-9a-fA-F\\.:\\%\\_/, ]+")) {
						System.err.println("Host value did not validate!");
						return new HashMap();
					}
					String[] routes = h.split(",\\s*");
					rFilter = new Route[routes.length];

					for (int x = 0; x < routes.length; x++) {
						rFilter[x] = new Route(routes[x]);
					}
				}

				if (values.containsKey("ports") && (values.get("ports") + "").length() > 0) {
					List ports = new LinkedList();
					List ports2 = new LinkedList();
					String[] p = (values.get("ports") + "").split(",\\s*");
					for (int x = 0; x < p.length; x++) {
						if (!p[x].matches("[0-9]+")) {
							return new HashMap();
						}

						ports.add("services.port = " + p[x]);
						//ports2.add("s.port = " + p[x]);
					}
					hosts.add("services.host_id = hosts.id");
					hosts.add("services.state = 'open'");
					hosts.add("(" + join(ports, " OR ") + ")");
				}

				if (values.containsKey("os") && (values.get("os") + "").length() > 0) {
					oFilter = (values.get("os") + "").toLowerCase().split(",\\s*");
				}

				/* label filter */
				if (values.containsKey("labels") && (values.get("labels") + "").length() > 0) {
					lFilter = (values.get("labels") + "").toLowerCase().split(",\\s*");
				}

				if (hosts.size() == 0) {
					hFilter = null;
				}
				else {
					hFilter = join(hosts, " AND ");
				}

				queries = build();
				return new HashMap();
			}
			else if (methodName.equals("db.fix_creds")) {
				Map values = (Map)params[0];
				PreparedStatement stmt = null;
				stmt = db.prepareStatement("UPDATE creds SET ptype = 'smb_hash' WHERE creds.user = ? AND creds.pass = ?");
				stmt.setString(1, values.get("user") + "");
				stmt.setString(2, values.get("pass") + "");

				Map result = new HashMap();
				result.put("rows", new Integer(stmt.executeUpdate()));
				return result;
			}
			else if (methodName.equals("db.report_labels")) {
				/* merge out global label data */
				Map values = (Map)params[0];
				mergeLabels(values);

				/* delete our saved label data */
				executeUpdate("DELETE FROM notes WHERE notes.ntype = 'armitage.labels'");

				/* serialize our notes data */
				ByteArrayOutputStream store = new ByteArrayOutputStream(labels.size() * 128);
				ObjectOutputStream handle = new ObjectOutputStream(store);
				handle.writeObject(labels);
				handle.close();
				store.close();

				String data = Base64.encode(store.toByteArray());

				/* save our label data */
				PreparedStatement stmt = null;
				stmt = db.prepareStatement("INSERT INTO notes (ntype, data) VALUES ('armitage.labels', ?)");
				stmt.setString(1, data);
				stmt.executeUpdate();

				return new HashMap();
			}
			else if (methodName.equals("db.report_host")) {
				Map values = (Map)params[0];
				String host = values.get("host") + "";
				PreparedStatement stmt = null;

				/* before we change this hosts info, kill its notes. We do this so future normalized data isn't ignored */
				executeUpdate("DELETE FROM notes WHERE EXISTS (SELECT id, address FROM hosts WHERE notes.host_id = id AND address = '" + host + "'::text::inet AND workspace_id = " + workspaceid + ")");

				if (values.containsKey("os_name") && values.containsKey("os_flavor")) {
					stmt = db.prepareStatement("UPDATE hosts SET os_name = ?, os_flavor = ?, os_sp = '' WHERE hosts.address = ?::text::inet AND hosts.workspace_id = " + workspaceid);
					stmt.setString(1, values.get("os_name") + "");
					stmt.setString(2, values.get("os_flavor") + "");
					stmt.setString(3, host);
				}
				else if (values.containsKey("os_name")) {
					stmt = db.prepareStatement("UPDATE hosts SET os_name = ?, os_flavor = '', os_sp = '' WHERE hosts.address = ?::text::inet AND hosts.workspace_id = " + workspaceid);
					stmt.setString(1, values.get("os_name") + "");
					stmt.setString(2, host);
				}
				else if (values.containsKey("purpose")) {
					stmt = db.prepareStatement("UPDATE hosts SET purpose = ? WHERE hosts.address = ?::text::inet AND hosts.workspace_id = " + workspaceid);
					stmt.setString(1, values.get("purpose") + "");
					stmt.setString(2, host);
				}
				else {
					return new HashMap();
				}

				Map result = new HashMap();
				result.put("rows", new Integer(stmt.executeUpdate()));
				return result;
			}
			else {
				System.err.println("Need to implement: " + methodName);
			}
		}
		catch (Exception ex) {
			System.err.println(ex);
			ex.printStackTrace();
		}

		return new HashMap();
	}
}
