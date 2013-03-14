<?c
#include <stdio.h>

void escape(char *str, FILE *out);

int main(int argc, char *argv[])
{
    int i;

?>
<p>Hello @!{argv[0]}@!</p>
<table>
  <tbody>
    <?c for (i = 1; i < argc; i++) { ?>
    <tr bgcolor="@{i % 2 == 0 ? "#FFCCCC" : "#CCCCFF"}@">
      <td>@!{"%d", i}@</td>
      <td>@{argv[i]}@</td>
    </tr>
    <?c } ?>
  </tbody>
</table>
<?c

    return 0; 
}

void escape(char *str, FILE *out)
{
    char *pch;
    for (pch = str; *pch != '\0'; pch++) {
        switch (*pch) {
        case '&':   fputs("&amp;",  out);  break;
        case '>':   fputs("&gt;",   out);  break;
        case '<':   fputs("&lt;",   out);  break;
        case '"':   fputs("&quot;", out);  break;
        case '\'':  fputs("&#039;", out);  break;
        default:    fputc(*pch, out);
        }
    }
}

?>
