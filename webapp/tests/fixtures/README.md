Files the browser tests upload:

- `clip.webm`: 3 s of test pattern and a tone (VP8 and Opus; the Chromium
  Playwright uses has no H.264). Made with:
  `ffmpeg -f lavfi -i testsrc=duration=3:size=160x120:rate=10 -f lavfi -i sine=frequency=440:duration=3 -c:v libvpx -b:v 50k -c:a libopus -b:a 24k -shortest clip.webm`
- `page.pdf`: one page that says "raft5fs", written by hand.
- `minutes.docx`: a Word file of two paragraphs, made with Python's
  `zipfile` (only `[Content_Types].xml` and `word/document.xml`).
- `text-vectors.json`: what native clients' text model gives for a few
  texts, with the browser's Q8_0 weights, for the parity test; written by
  raft5fs-indexer's ignored test `write_the_web_apps_parity_fixture`.
- `clip-vectors.json`: the same, for the photo model's text side; written
  by raft5fs-indexer's ignored test `write_the_web_apps_clip_fixture`.
- `lisbon.jpg`: the search crate's `lake.jpg` with EXIF data saying it was
  taken in Lisbon in June 2024 on an iPhone; written by raft5fs-search's
  ignored test `write_the_web_apps_photo_fixture`.
