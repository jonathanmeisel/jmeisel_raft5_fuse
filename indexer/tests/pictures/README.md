Pictures for the CLIP tests, drawn with ImageMagick (320 by 240):

- `beach.jpg`: sky, sea and sand, and a sun;
- `forest.jpg`: green, with brown trunks and round crowns;
- `stop.jpg`: a red octagon that says STOP;
- `cake.jpg`: the words BIRTHDAY CAKE.

The search crate's `src/extract/testdata/lake.jpg` (a blue gradient and a
white circle) was made the same way:
`magick -size 320x240 gradient:skyblue-navy -fill white -draw "circle 160,120 160,60" -quality 80 lake.jpg`.
