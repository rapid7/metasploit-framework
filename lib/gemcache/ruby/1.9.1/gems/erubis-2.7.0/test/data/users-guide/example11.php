<?xml version="1.0"?>
<html>
  <body>
    <h3>List</h3>
    <?php if (!$list) { ?>
    <p>not found.</p>
    <?php } else { ?>
    <table>
      <tbody>
        <?php $i = 0; ?>
        <?php foreach ($list as $item) { ?>
        <tr bgcolor="<?php echo ++$i % 2 == 1 ? '#FCC' : '#CCF'; ?>">
          <td><?php echo $item; ?></td>
        </tr>
        <?php } ?>
      </tbody>
    </table>
    <?php } ?>
  </body>
</html>
