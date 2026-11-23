//! Builds `data/places.bin` (see `geo`) from:
//!
//! - GeoNames (CC BY 4.0): `cities1000.txt` (places of 1000 people or more,
//!   less sections of towns and places that are gone)
//!   and `countryInfo.txt`, from https://download.geonames.org/export/dump/;
//! - Natural Earth (public domain): `ne_10m_admin_1_states_provinces.geojson`
//!   from the natural-earth-vector repository.
//!
//! GeoNames changes daily, so the output is committed, not rebuilt each
//! time; clients check it against the SHA-256 that `geo::PLACES_SHA256`
//! pins. Usage:
//!
//!   cargo run --release -p raft5fs-search --example build_places -- <dir> <out>

use std::collections::HashMap;

use raft5fs_search::geo::{Country, Places, Region, Table, Town, encode, simplify};

/// About 500 m, in 1e-4 degree units.
const TOLERANCE: f64 = 50.0;

fn units(deg: f64) -> i32 {
    (deg * 1e4).round() as i32
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let (dir, out) = (&args[1], &args[2]);
    let read = |name: &str| std::fs::read_to_string(format!("{dir}/{name}")).expect(name);

    let mut table = Table::default();
    let mut country_of: HashMap<String, u16> = HashMap::new();
    for line in read("countryInfo.txt")
        .lines()
        .filter(|l| !l.starts_with('#'))
    {
        let f: Vec<&str> = line.split('\t').collect();
        if f.len() > 4 && !f[0].is_empty() {
            country_of.insert(f[0].to_string(), table.countries.len() as u16);
            table.countries.push(Country {
                code: f[0].into(),
                name: f[4].into(),
            });
        }
    }

    let geojson: serde_json::Value =
        serde_json::from_str(&read("ne_10m_admin_1_states_provinces.geojson")).expect("geojson");
    let mut before = 0usize;
    let mut after = 0usize;
    for feature in geojson["features"].as_array().unwrap() {
        let p = &feature["properties"];
        let own = p["name"].as_str().unwrap_or_default().to_string();
        let english = p["name_en"].as_str().unwrap_or_default().to_string();
        let (name, local) = match (own, english) {
            (own, english) if english.is_empty() || english == own => (own, String::new()),
            (own, english) if own.is_empty() => (english, String::new()),
            (own, english) => (english, own),
        };
        let iso = p["iso_a2"].as_str().unwrap_or("-1").to_string();
        let country = match country_of.get(&iso) {
            Some(&c) => c,
            None => {
                let admin = p["admin"].as_str().unwrap_or("").to_string();
                let c = table.countries.len() as u16;
                country_of.insert(iso.clone(), c);
                table.countries.push(Country {
                    code: iso,
                    name: admin,
                });
                c
            }
        };
        let g = &feature["geometry"];
        let polygons: Vec<&serde_json::Value> = match g["type"].as_str() {
            Some("Polygon") => vec![&g["coordinates"]],
            Some("MultiPolygon") => g["coordinates"].as_array().unwrap().iter().collect(),
            _ => continue,
        };
        let mut rings = Vec::new();
        for poly in polygons {
            for ring in poly.as_array().unwrap() {
                let pts: Vec<(i32, i32)> = ring
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|p| (units(p[0].as_f64().unwrap()), units(p[1].as_f64().unwrap())))
                    .collect();
                before += pts.len();
                let s = simplify(&pts, TOLERANCE);
                // A ring smaller than the tolerance is an islet: drop it.
                if s.len() >= 3 {
                    after += s.len();
                    rings.push(s);
                }
            }
        }
        if name.is_empty() || rings.is_empty() {
            continue;
        }
        table.regions.push(Region {
            country,
            name,
            local,
            rings,
        });
    }
    eprintln!("region points: {before} -> {after}");

    // Each town's region, by its point.
    let regions = Places::new(Table {
        countries: table.countries.clone(),
        regions: table.regions.clone(),
        towns: Vec::new(),
    });
    let mut towns = Vec::new();
    for line in read("cities1000.txt").lines() {
        let f: Vec<&str> = line.split('\t').collect();
        if f.len() < 11 {
            continue;
        }
        let (lat, lon) = (f[4].parse::<f64>().unwrap(), f[5].parse::<f64>().unwrap());
        // Sections of a town (city districts), and historical, abandoned
        // or destroyed places, aren't what a place is called.
        if matches!(f[7], "PPLX" | "PPLH" | "PPLQ" | "PPLW") {
            continue;
        }
        let Some(&country) = country_of.get(f[8]) else {
            continue;
        };
        let at = regions.locate(lat, lon);
        let region = at
            .region
            .and_then(|name| {
                table
                    .regions
                    .iter()
                    .position(|r| r.name == name && r.country == country)
            })
            .map_or(u16::MAX, |i| i as u16);
        towns.push(Town {
            name: f[1].into(),
            lat: units(lat),
            lon: units(lon),
            region,
            country,
        });
    }
    // In bands of latitude, then by longitude: both deltas stay small.
    towns.sort_by_key(|t| (t.lat.div_euclid(5_000), t.lon, t.lat));
    table.towns = towns;
    let bytes = encode(&table);
    eprintln!(
        "{} countries, {} regions, {} towns: {} bytes",
        table.countries.len(),
        table.regions.len(),
        table.towns.len(),
        bytes.len()
    );
    std::fs::write(out, bytes).unwrap();
}
