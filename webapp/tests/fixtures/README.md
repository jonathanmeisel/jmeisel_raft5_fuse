Files the browser tests upload:

- `clip.webm`: 3 s of test pattern and a tone (VP8 and Opus; the Chromium
  Playwright uses has no H.264). Made with:
  `ffmpeg -f lavfi -i testsrc=duration=3:size=160x120:rate=10 -f lavfi -i sine=frequency=440:duration=3 -c:v libvpx -b:v 50k -c:a libopus -b:a 24k -shortest clip.webm`
- `page.pdf`: one page that says "raft5fs", written by hand.
