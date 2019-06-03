`play_youtube` allows you to open and start playing a YouTube video on a
compromised host.

## Important Options

**EMBED**

Whether or not to use the `/embed` YouTube URL. The embeded version provides a
clean interface and will start playing in fullscreen but is not compatible with
all YouTube videos, for example Rick Astley - Never Gonna Give You Up (VID:
[`dQw4w9WgXcQ`][1]) is not compatible.

While the non-embeded version has greater compatibility, there is a chance that
an advertisement may be played before the video. It is recommended to use the
embeded version when the video is compatible.

**VID**

The video's identifier on YouTube. This is the `v` parameter of the URL.

## See Also

* Meterpreter's `uictl` command in the `stdapi` extension for enabling and
  disabling the mouse and keyboard.

[1]: https://www.youtube.com/watch?v=dQw4w9WgXcQ
