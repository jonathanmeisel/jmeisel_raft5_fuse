`places.bin` is the places table (see `src/geo.rs`) that every client uses
to name where tracks and photos are, offline. It is made from:

- [GeoNames](https://www.geonames.org/) (CC BY 4.0): places of 1000 people
  or more (`cities1000.txt`) and `countryInfo.txt`, as published on
  2026-11-22;
- [Natural Earth](https://www.naturalearthdata.com/) (public domain): states
  and provinces, `ne_10m_admin_1_states_provinces.geojson` at
  natural-earth-vector commit `ca96624a56bd078437bca8184e78163e5039ad19`,
  simplified to about 500 m.

GeoNames changes daily, so the table is committed, not built each time.
Clients check it against `geo::PLACES_SHA256`. To make it again, put those
three files in a folder and run

    cargo run --release -p raft5fs-search --example build_places -- <folder> search/data/places.bin

then set `PLACES_SHA256` to the new file's SHA-256.
