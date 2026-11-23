//! Places, offline: which town, state or province, and country a point is
//! in, from a table that every client keeps (`places.bin`, made by the
//! `build-places` example from GeoNames and Natural Earth). Nothing is
//! asked of any server, so where a photo or a ride was stays on the device.
//!
//! - **Regions** (states, provinces) are polygons, simplified to about
//!   500 m, so a point near a border gets the right side unless it is
//!   closer to it than that.
//! - **Towns** are GeoNames places of 1000 people or more; a point's town
//!   is the nearest within `TOWN_KM`.
//! - A point in no region's polygon (a coast that simplifying moved) takes
//!   the region of its nearest town.
//!
//! The file: magic, format, then countries, regions and towns. Numbers are
//! LEB128 varints, coordinates in 1e-4 degrees (about 11 m), a ring's
//! points as zigzag deltas from the one before.

use std::collections::HashMap;

use crate::Error;

/// The SHA-256 of the table every client uses (`data/places.bin`). The web
/// app checks what it downloads against it.
pub const PLACES_SHA256: &str = "01d2df2a4cf73c482d7bfc7ffaeb617dda74bef209dea738e13ad6c7b601a2d6";

const MAGIC: &[u8; 4] = b"r5pl";
const FORMAT: u8 = 1;
/// How far a town can be from a point and still be its town.
pub const TOWN_KM: f64 = 12.0;
/// Coordinates are kept in this many units per degree.
const SCALE: f64 = 1e4;
/// The size of the cells that towns are filed in, in units.
const CELL: i32 = 5_000;

#[derive(Debug, Clone, PartialEq)]
pub struct Country {
    pub code: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Region {
    pub country: u16,
    /// Its English name where Natural Earth has one, else its own.
    pub name: String,
    /// Its own name, where that is another: "Lisboa" for Lisbon. Empty
    /// for none.
    pub local: String,
    /// Rings of (longitude, latitude) in units; holes are rings too (a
    /// point is inside if an odd number of rings hold it).
    pub rings: Vec<Vec<(i32, i32)>>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Town {
    pub name: String,
    pub lat: i32,
    pub lon: i32,
    /// Its region, or `u16::MAX` for none.
    pub region: u16,
    pub country: u16,
}

/// The whole table.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Table {
    pub countries: Vec<Country>,
    pub regions: Vec<Region>,
    pub towns: Vec<Town>,
}

/// Where a point is, as names.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Place {
    pub town: Option<String>,
    pub region: Option<String>,
    /// The region's own name, where it has another.
    pub region_local: Option<String>,
    pub country: Option<String>,
}

impl Place {
    /// Every name, for search to find: town, region (both its names),
    /// country.
    pub fn names(&self) -> Vec<String> {
        [&self.town, &self.region, &self.region_local, &self.country]
            .into_iter()
            .flatten()
            .cloned()
            .collect()
    }
}

fn put_varint(out: &mut Vec<u8>, mut n: u64) {
    loop {
        let byte = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

fn zigzag(n: i64) -> u64 {
    ((n << 1) ^ (n >> 63)) as u64
}

fn unzigzag(n: u64) -> i64 {
    ((n >> 1) as i64) ^ -((n & 1) as i64)
}

fn put_str(out: &mut Vec<u8>, s: &str) {
    put_varint(out, s.len() as u64);
    out.extend_from_slice(s.as_bytes());
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn bad(&self) -> Error {
        raft5fs_wire::Reader::new(&[], "a places table").garbled()
    }

    fn byte(&mut self) -> Result<u8, Error> {
        let b = *self.bytes.get(self.at).ok_or_else(|| self.bad())?;
        self.at += 1;
        Ok(b)
    }

    fn varint(&mut self) -> Result<u64, Error> {
        let mut n = 0u64;
        for shift in (0..64).step_by(7) {
            let b = self.byte()?;
            n |= u64::from(b & 0x7f) << shift;
            if b & 0x80 == 0 {
                return Ok(n);
            }
        }
        Err(self.bad())
    }

    fn signed(&mut self) -> Result<i64, Error> {
        Ok(unzigzag(self.varint()?))
    }

    fn str(&mut self) -> Result<String, Error> {
        let len = self.varint()? as usize;
        let end = self.at.checked_add(len).ok_or_else(|| self.bad())?;
        let s = self.bytes.get(self.at..end).ok_or_else(|| self.bad())?;
        self.at = end;
        String::from_utf8(s.to_vec()).map_err(|_| self.bad())
    }
}

pub fn encode(t: &Table) -> Vec<u8> {
    let mut out = MAGIC.to_vec();
    out.push(FORMAT);
    put_varint(&mut out, t.countries.len() as u64);
    for c in &t.countries {
        put_str(&mut out, &c.code);
        put_str(&mut out, &c.name);
    }
    put_varint(&mut out, t.regions.len() as u64);
    for r in &t.regions {
        put_varint(&mut out, u64::from(r.country));
        put_str(&mut out, &r.name);
        put_str(&mut out, &r.local);
        put_varint(&mut out, r.rings.len() as u64);
        for ring in &r.rings {
            put_varint(&mut out, ring.len() as u64);
            let mut last = (0i64, 0i64);
            for &(x, y) in ring {
                put_varint(&mut out, zigzag(i64::from(x) - last.0));
                put_varint(&mut out, zigzag(i64::from(y) - last.1));
                last = (i64::from(x), i64::from(y));
            }
        }
    }
    put_varint(&mut out, t.towns.len() as u64);
    let mut last = (0i64, 0i64);
    for town in &t.towns {
        put_str(&mut out, &town.name);
        put_varint(&mut out, zigzag(i64::from(town.lat) - last.0));
        put_varint(&mut out, zigzag(i64::from(town.lon) - last.1));
        last = (i64::from(town.lat), i64::from(town.lon));
        put_varint(&mut out, u64::from(town.region));
        put_varint(&mut out, u64::from(town.country));
    }
    out
}

pub fn decode(bytes: &[u8]) -> Result<Table, Error> {
    let mut r = Reader { bytes, at: 0 };
    let magic: Vec<u8> = (0..4).map(|_| r.byte()).collect::<Result<_, _>>()?;
    if magic != MAGIC || r.byte()? != FORMAT {
        return Err(r.bad());
    }
    let mut t = Table::default();
    for _ in 0..r.varint()? {
        t.countries.push(Country {
            code: r.str()?,
            name: r.str()?,
        });
    }
    for _ in 0..r.varint()? {
        let country = u16::try_from(r.varint()?).map_err(|_| r.bad())?;
        let name = r.str()?;
        let local = r.str()?;
        let mut rings = Vec::new();
        for _ in 0..r.varint()? {
            let n = r.varint()? as usize;
            let mut ring = Vec::with_capacity(n.min(1 << 20));
            let mut last = (0i64, 0i64);
            for _ in 0..n {
                last.0 += r.signed()?;
                last.1 += r.signed()?;
                ring.push((last.0 as i32, last.1 as i32));
            }
            rings.push(ring);
        }
        t.regions.push(Region {
            country,
            name,
            local,
            rings,
        });
    }
    let mut last = (0i64, 0i64);
    for _ in 0..r.varint()? {
        let name = r.str()?;
        last.0 += r.signed()?;
        last.1 += r.signed()?;
        let region = u16::try_from(r.varint()?).map_err(|_| r.bad())?;
        let country = u16::try_from(r.varint()?).map_err(|_| r.bad())?;
        t.towns.push(Town {
            name,
            lat: last.0 as i32,
            lon: last.1 as i32,
            region,
            country,
        });
    }
    if r.at != bytes.len() {
        return Err(r.bad());
    }
    Ok(t)
}

/// Whether `p` is inside `ring` (a closed or open polygon), by crossings.
fn in_ring(ring: &[(i32, i32)], p: (i32, i32)) -> bool {
    let mut inside = false;
    let (px, py) = (f64::from(p.0), f64::from(p.1));
    let n = ring.len();
    for i in 0..n {
        let (x1, y1) = (f64::from(ring[i].0), f64::from(ring[i].1));
        let (x2, y2) = (
            f64::from(ring[(i + 1) % n].0),
            f64::from(ring[(i + 1) % n].1),
        );
        if (y1 > py) != (y2 > py) && px < x1 + (py - y1) * (x2 - x1) / (y2 - y1) {
            inside = !inside;
        }
    }
    inside
}

/// Kilometres between two points in units, near enough at town scale.
fn km(a: (i32, i32), b: (i32, i32)) -> f64 {
    let lat = (f64::from(a.0 + b.0) / 2.0 / SCALE).to_radians();
    let dy = f64::from(a.0 - b.0) / SCALE * 111.32;
    let dx = f64::from(a.1 - b.1) / SCALE * 111.32 * lat.cos();
    (dx * dx + dy * dy).sqrt()
}

fn cell(lat: i32, lon: i32) -> (i32, i32) {
    (lat.div_euclid(CELL), lon.div_euclid(CELL))
}

/// The table, ready for lookups.
pub struct Places {
    table: Table,
    /// Each region's bounding box: min lon, min lat, max lon, max lat.
    boxes: Vec<(i32, i32, i32, i32)>,
    /// Towns by cell.
    grid: HashMap<(i32, i32), Vec<u32>>,
}

impl Places {
    pub fn new(table: Table) -> Self {
        let boxes = table
            .regions
            .iter()
            .map(|r| {
                r.rings.iter().flatten().fold(
                    (i32::MAX, i32::MAX, i32::MIN, i32::MIN),
                    |(a, b, c, d), &(x, y)| (a.min(x), b.min(y), c.max(x), d.max(y)),
                )
            })
            .collect();
        let mut grid: HashMap<(i32, i32), Vec<u32>> = HashMap::new();
        for (i, t) in table.towns.iter().enumerate() {
            grid.entry(cell(t.lat, t.lon)).or_default().push(i as u32);
        }
        Self { table, boxes, grid }
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        Ok(Self::new(decode(bytes)?))
    }

    fn region_at(&self, p: (i32, i32)) -> Option<u16> {
        let (lon, lat) = p;
        self.boxes
            .iter()
            .enumerate()
            .filter(|(_, b)| lon >= b.0 && lat >= b.1 && lon <= b.2 && lat <= b.3)
            .find(|(i, _)| {
                self.table.regions[*i]
                    .rings
                    .iter()
                    .filter(|ring| in_ring(ring, p))
                    .count()
                    % 2
                    == 1
            })
            .map(|(i, _)| i as u16)
    }

    /// The nearest town to (`lat`, `lon`) in units, and how far it is.
    fn nearest_town(&self, lat: i32, lon: i32) -> Option<(&Town, f64)> {
        let (cy, cx) = cell(lat, lon);
        let mut best: Option<(&Town, f64)> = None;
        for dy in -1..=1 {
            for dx in -1..=1 {
                for &i in self.grid.get(&(cy + dy, cx + dx)).into_iter().flatten() {
                    let t = &self.table.towns[i as usize];
                    let d = km((lat, lon), (t.lat, t.lon));
                    if best.is_none_or(|(_, b)| d < b) {
                        best = Some((t, d));
                    }
                }
            }
        }
        best
    }

    /// Where (`lat`, `lon`), in degrees, is.
    pub fn locate(&self, lat: f64, lon: f64) -> Place {
        let p = ((lat * SCALE).round() as i32, (lon * SCALE).round() as i32);
        let town = self.nearest_town(p.0, p.1);
        let region = self.region_at((p.1, p.0)).or_else(|| {
            town.filter(|(_, d)| *d <= TOWN_KM * 2.0)
                .map(|(t, _)| t.region)
                .filter(|&r| r != u16::MAX)
        });
        let country = region
            .map(|r| self.table.regions[r as usize].country)
            .or_else(|| {
                town.filter(|(_, d)| *d <= TOWN_KM * 2.0)
                    .map(|(t, _)| t.country)
            });
        Place {
            town: town
                .filter(|(_, d)| *d <= TOWN_KM)
                .map(|(t, _)| t.name.clone()),
            region: region.map(|r| self.table.regions[r as usize].name.clone()),
            region_local: region
                .map(|r| self.table.regions[r as usize].local.clone())
                .filter(|l| !l.is_empty()),
            country: country
                .and_then(|c| self.table.countries.get(c as usize))
                .map(|c| c.name.clone()),
        }
    }
}

/// Douglas–Peucker: `ring` with points closer than `tolerance` (in units)
/// to the line between their neighbours left out. A ring keeps at least
/// its first, middle and last points.
pub fn simplify(ring: &[(i32, i32)], tolerance: f64) -> Vec<(i32, i32)> {
    if ring.len() <= 4 {
        return ring.to_vec();
    }
    let mut keep = vec![false; ring.len()];
    keep[0] = true;
    keep[ring.len() - 1] = true;
    let mid = ring.len() / 2;
    keep[mid] = true;
    let mut stack = vec![(0, mid), (mid, ring.len() - 1)];
    while let Some((a, b)) = stack.pop() {
        if b <= a + 1 {
            continue;
        }
        let (ax, ay) = (f64::from(ring[a].0), f64::from(ring[a].1));
        let (bx, by) = (f64::from(ring[b].0), f64::from(ring[b].1));
        let len = ((bx - ax).powi(2) + (by - ay).powi(2)).sqrt();
        let (mut far, mut at) = (0.0, a);
        for (i, &(x, y)) in ring.iter().enumerate().take(b).skip(a + 1) {
            let (x, y) = (f64::from(x), f64::from(y));
            let d = if len == 0.0 {
                ((x - ax).powi(2) + (y - ay).powi(2)).sqrt()
            } else {
                ((bx - ax) * (ay - y) - (ax - x) * (by - ay)).abs() / len
            };
            if d > far {
                far = d;
                at = i;
            }
        }
        if far > tolerance {
            keep[at] = true;
            stack.push((a, at));
            stack.push((at, b));
        }
    }
    ring.iter()
        .zip(keep)
        .filter_map(|(&p, k)| k.then_some(p))
        .collect()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Two regions side by side, split at longitude -72 (in units), and
    /// a few towns.
    pub(crate) fn sample() -> Places {
        let square =
            |x0: i32, x1: i32| vec![(x0, 420_000), (x1, 420_000), (x1, 450_000), (x0, 450_000)];
        let town = |name: &str, lat: i32, lon: i32, region: u16| Town {
            name: name.into(),
            lat,
            lon,
            region,
            country: 0,
        };
        Places::new(Table {
            countries: vec![Country {
                code: "US".into(),
                name: "United States".into(),
            }],
            regions: vec![
                Region {
                    country: 0,
                    name: "Vermont".into(),
                    local: String::new(),
                    rings: vec![square(-735_000, -720_000)],
                },
                Region {
                    country: 0,
                    name: "New Hampshire".into(),
                    local: String::new(),
                    rings: vec![square(-720_000, -705_000)],
                },
            ],
            towns: vec![
                town("Lyndonville", 445_300, -720_100, 0),
                town("Littleton", 443_100, -717_700, 1),
                town("Burlington", 444_800, -732_100, 0),
            ],
        })
    }

    #[test]
    fn a_point_gets_its_region_town_and_country() {
        let places = sample();
        let p = places.locate(44.53, -72.02);
        assert_eq!(p.region.as_deref(), Some("Vermont"));
        assert_eq!(p.town.as_deref(), Some("Lyndonville"));
        assert_eq!(p.country.as_deref(), Some("United States"));
        // Across the line, a few km away: the other state, though the
        // nearest town is still in the first.
        let p = places.locate(44.53, -71.98);
        assert_eq!(p.region.as_deref(), Some("New Hampshire"));
        // Far from any town, and outside every region.
        let p = places.locate(10.0, 10.0);
        assert_eq!(p, Place::default());
    }

    #[test]
    fn a_table_round_trips_and_refuses_damage() {
        let t = sample().table;
        let bytes = encode(&t);
        assert_eq!(decode(&bytes).unwrap(), t);
        assert!(decode(&bytes[..bytes.len() - 1]).is_err());
        assert!(decode(b"nope").is_err());
    }

    #[test]
    fn simplifying_drops_points_on_a_line_and_keeps_corners() {
        let mut ring: Vec<(i32, i32)> = (0..100).map(|i| (i, 0)).collect();
        ring.extend((0..100).map(|i| (100, i)));
        let out = simplify(&ring, 1.0);
        assert!(out.len() <= 5, "{out:?}");
        assert!(out.contains(&(100, 0)), "the corner stays: {out:?}");
    }

    #[test]
    fn the_table_is_the_one_clients_pin() {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(include_bytes!("../data/places.bin"));
        assert_eq!(raft5fs_wire::hex(&digest), PLACES_SHA256);
    }

    /// The table every client keeps.
    #[test]
    fn the_real_table_puts_places_where_they_are() {
        let places = Places::decode(include_bytes!("../data/places.bin")).unwrap();
        let at = |lat, lon| places.locate(lat, lon);
        let p = at(44.5361, -72.0053);
        assert_eq!(
            (p.town.as_deref(), p.region.as_deref(), p.country.as_deref()),
            (Some("Lyndonville"), Some("Vermont"), Some("United States"))
        );
        // Two towns 2 km apart, on each side of the Connecticut River, the
        // border between Vermont and New Hampshire.
        assert_eq!(
            at(43.7153, -72.3079).region.as_deref(),
            Some("Vermont"),
            "Norwich"
        );
        assert_eq!(
            at(43.7022, -72.2896).region.as_deref(),
            Some("New Hampshire"),
            "Hanover"
        );
        assert_eq!(at(38.7223, -9.1393).country.as_deref(), Some("Portugal"));
        assert_eq!(at(35.6895, 139.6917).country.as_deref(), Some("Japan"));
        // The middle of the Atlantic: nothing.
        assert_eq!(at(30.0, -40.0), Place::default());
    }
}
