#
# Screenshot viewer... whee?!?
#
import java.awt.*;
import java.awt.event.*;

import javax.swing.*;
import javax.swing.event.*;
import javax.imageio.*;
import java.io.File;

import ui.*;

import armitage.*;

global('%screenshots %webcams');
%screenshots = ohash();
%webcams = ohash();

sub image_viewer
{
	local('$panel $viewer $buttons $refresh $watch');

	$panel = [new JPanel];
	[$panel setLayout: [new BorderLayout]];

		$viewer = [new ZoomableImage];
		[$panel add: [new JScrollPane: $viewer], [BorderLayout CENTER]];

		$buttons = [new JPanel];
		[$buttons setLayout: [new FlowLayout: [FlowLayout CENTER]]];
			$refresh = [new JButton: "Refresh"];
			[$refresh addActionListener: lambda({
				m_cmd($sid, $command);
			}, $sid => $2, \$command)];
			[$buttons add: $refresh];

			$watch = [new JButton: "Watch (10s)"];
			[$watch addActionListener: lambda({
				local('$timer');
				$timer = [new SimpleTimer: 10000];
				[$timer setRunnable: lambda({
					if ($sid !in $container) {
						[$timer stop];
					}
					else {
						m_cmd($sid, $command);
					}
				}, \$sid, \$timer, \$container, \$command)];
			}, $sid => $2, \$container, \$command)];
			[$buttons add: $watch];
		[$panel add: $buttons, [BorderLayout SOUTH]];
	
	[$frame addTab: "$title $2", $panel, lambda({ $container[$key] = $null; size($container); }, $key => $2, \$container), "$title " . sessionToHost($2)];
	return $viewer;
}

sub update_viewer {
	if ($0 eq "update" && "*Operation failed*" iswm $2) {
		showError($2);
	}
	else if ($0 eq "update" && $2 ismatch "$type saved to: (.*?)") {
		local('$file $image $panel');
		($file) = matched();

		# we're collaborating, so download the file please...
		if ($client !is $mclient) {
			$file = getFileProper(cwd(), downloadFile($file));
		}

		logFile($file, sessionToHost($1), $type);
		$image = [ImageIO read: [new File: $file]];

		fire_event_async("user_" . lc(strrep($type, " ", "_")), $1, $file);

		dispatchEvent(lambda({
			[$container[$id] setIcon: [new ImageIcon: $image]];
		}, \$container, \$image, $id => $1));

		if (-isFile $file && "*.jpeg" iswm $file) { 
			deleteOnExit($file);
		}
	}
}

setMissPolicy(%screenshots, lambda(&image_viewer, $title => "Screenshot", $command => "screenshot -v false", $container => %screenshots));
setMissPolicy(%webcams, lambda(&image_viewer, $title => "Webcam", $command => "webcam_snap -v false", $container => %webcams));

%handlers["screenshot"] = lambda(&update_viewer, $type => "Screenshot", $container => %screenshots);
%handlers["webcam_snap"] = lambda(&update_viewer, $type => "Webcam shot", $container => %webcams);

sub createScreenshotViewer {
	return lambda({
		m_cmd($sid, "screenshot -v false");
	}, $sid => $1);
}

sub createWebcamViewer {
	return lambda({
		m_cmd($sid, "webcam_snap -v false");
	}, $sid => $1);
}
