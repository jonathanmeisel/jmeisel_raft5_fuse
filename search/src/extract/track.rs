//! GPS tracks and routes: GPX and TCX, read into one `Track`, and the text
//! that search finds a track by.
//!
//! - A GPX `<trk>` and a TCX `<Activity>` are recorded; a GPX `<rte>` and a
//!   TCX `<Course>` are planned routes.
//! - The text has the names, descriptions, the kind of track and activity,
//!   the month it started, its distance and its climbing, and with a
//!   places table (`geo`), the towns, regions and countries it goes
//!   through, from a point every `PLACE_EVERY_M`.

use quick_xml::events::{BytesStart, Event};
use quick_xml::reader::Reader;

use super::{Extracted, READER};
use crate::geo::Places;
use crate::record::{DocKind, Extra};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TrackKind {
    #[default]
    Recorded,
    Route,
}

/// What a GPX or TCX file says, in one form.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Track {
    pub kind: TrackKind,
    /// Names and descriptions: of the track, its waypoints, course points.
    pub texts: Vec<String>,
    /// As the file says it ("cycling", "Biking").
    pub activity: Option<String>,
    /// As the file says it, ISO 8601.
    pub start: Option<String>,
    /// Latitude, longitude, elevation (m).
    pub points: Vec<(f64, f64, Option<f64>)>,
    /// From the file if it says (TCX laps); else from the points.
    pub distance_m: f64,
    pub climb_m: f64,
}

/// The local name of an element, as text.
fn name_of(e: &BytesStart<'_>) -> String {
    String::from_utf8_lossy(e.local_name().as_ref()).into_owned()
}

fn attr_f64(e: &BytesStart<'_>, key: &str) -> Option<f64> {
    let a = e.try_get_attribute(key).ok()??;
    std::str::from_utf8(&a.value).ok()?.trim().parse().ok()
}

fn attr_str(e: &BytesStart<'_>, key: &str) -> Option<String> {
    let a = e.try_get_attribute(key).ok()??;
    Some(String::from_utf8_lossy(&a.value).into_owned())
}

/// One step of `walk`, with the names of the open elements.
enum Step<'a, 'b> {
    Start(&'a [String], &'a BytesStart<'b>),
    Text(&'a [String], &'a str),
    End(&'a [String]),
}

/// Reads XML as a stack of element names, and calls `on` for each element
/// that opens, each text node, and each element that closes. `None` if the
/// XML does not parse.
fn walk(xml: &[u8], mut on: impl FnMut(Step<'_, '_>)) -> Option<()> {
    let mut reader = Reader::from_reader(xml);
    let mut buf = Vec::new();
    let mut stack: Vec<String> = Vec::new();
    loop {
        match reader.read_event_into(&mut buf).ok()? {
            Event::Start(e) => {
                stack.push(name_of(&e));
                on(Step::Start(&stack, &e));
            }
            Event::Empty(e) => {
                stack.push(name_of(&e));
                on(Step::Start(&stack, &e));
                on(Step::End(&stack));
                stack.pop();
            }
            Event::End(_) => {
                on(Step::End(&stack));
                stack.pop();
            }
            Event::Text(t) => on(Step::Text(&stack, t.unescape().ok()?.trim())),
            Event::CData(t) => on(Step::Text(&stack, String::from_utf8_lossy(&t).trim())),
            Event::Eof => return Some(()),
            _ => {}
        }
        buf.clear();
    }
}

fn last(stack: &[String]) -> &str {
    stack.last().map_or("", String::as_str)
}

fn parent(stack: &[String]) -> &str {
    stack.len().checked_sub(2).map_or("", |i| stack[i].as_str())
}

pub fn parse_gpx(xml: &[u8]) -> Option<Track> {
    let mut t = Track::default();
    let mut saw_trk = false;
    let mut saw_rte = false;
    walk(xml, |step| match step {
        Step::Start(stack, e) => match last(stack) {
            "trk" => saw_trk = true,
            "rte" => saw_rte = true,
            "trkpt" | "rtept" => {
                if let (Some(lat), Some(lon)) = (attr_f64(e, "lat"), attr_f64(e, "lon")) {
                    t.points.push((lat, lon, None));
                }
            }
            _ => {}
        },
        Step::Text(_, "") | Step::End(_) => {}
        Step::Text(stack, text) => match (parent(stack), last(stack)) {
            ("trkpt" | "rtept", "ele") => {
                if let (Some(p), Ok(ele)) = (t.points.last_mut(), text.parse()) {
                    p.2 = Some(ele);
                }
            }
            ("trkpt", "time") if t.start.is_none() => t.start = Some(text.to_string()),
            ("metadata", "time") if t.start.is_none() => t.start = Some(text.to_string()),
            ("trk" | "rte", "type") => t.activity = Some(text.to_string()),
            ("trk" | "rte" | "wpt" | "metadata", "name" | "desc" | "cmt") => {
                t.texts.push(text.to_string())
            }
            ("rtept" | "trkpt", "name") => t.texts.push(text.to_string()),
            _ => {}
        },
    })?;
    t.kind = if saw_rte && !saw_trk {
        TrackKind::Route
    } else {
        TrackKind::Recorded
    };
    t.distance_m = path_length(&t.points);
    t.climb_m = climb(&t.points);
    Some(t)
}

pub fn parse_tcx(xml: &[u8]) -> Option<Track> {
    let mut t = Track::default();
    let mut lap_distance = 0.0;
    let mut saw_course = false;
    let (mut lat, mut lon) = (None, None);
    walk(xml, |step| match step {
        Step::Start(stack, e) => match last(stack) {
            "Activity" => t.activity = attr_str(e, "Sport").or(t.activity.take()),
            "Course" => saw_course = true,
            "Trackpoint" => (lat, lon) = (None, None),
            _ => {}
        },
        Step::Text(_, "") => {}
        Step::Text(stack, text) => match (parent(stack), last(stack)) {
            ("Position", "LatitudeDegrees") => lat = text.parse().ok(),
            ("Position", "LongitudeDegrees") => lon = text.parse().ok(),
            ("Trackpoint", "AltitudeMeters") => {
                if let (Some(p), Ok(ele)) = (t.points.last_mut(), text.parse()) {
                    p.2 = Some(ele);
                }
            }
            ("Activity", "Id") if t.start.is_none() => t.start = Some(text.to_string()),
            ("Lap", "DistanceMeters") => lap_distance += text.parse::<f64>().unwrap_or(0.0),
            ("Activity" | "Course" | "CoursePoint", "Name" | "Notes") => {
                t.texts.push(text.to_string())
            }
            ("Lap", "Notes") => t.texts.push(text.to_string()),
            _ => {}
        },
        // A point is complete once its position is read; its altitude, if
        // any, comes after it in the file.
        Step::End(stack) => {
            if last(stack) == "Position"
                && let (Some(la), Some(lo)) = (lat, lon)
            {
                t.points.push((la, lo, None));
            }
        }
    })?;
    t.kind = if saw_course {
        TrackKind::Route
    } else {
        TrackKind::Recorded
    };
    t.distance_m = if lap_distance > 0.0 {
        lap_distance
    } else {
        path_length(&t.points)
    };
    t.climb_m = climb(&t.points);
    Some(t)
}

/// Metres between two points on a sphere the size of the Earth.
fn haversine(a: (f64, f64), b: (f64, f64)) -> f64 {
    const R: f64 = 6_371_000.0;
    let (la1, la2) = (a.0.to_radians(), b.0.to_radians());
    let dla = la2 - la1;
    let dlo = (b.1 - a.1).to_radians();
    let h = (dla / 2.0).sin().powi(2) + la1.cos() * la2.cos() * (dlo / 2.0).sin().powi(2);
    2.0 * R * h.sqrt().asin()
}

fn path_length(points: &[(f64, f64, Option<f64>)]) -> f64 {
    points
        .windows(2)
        .map(|w| haversine((w[0].0, w[0].1), (w[1].0, w[1].1)))
        .sum()
}

/// Metres climbed. GPS elevation wanders by a few metres, so a climb counts
/// only once it is `NOISE_M` above the last low point.
fn climb(points: &[(f64, f64, Option<f64>)]) -> f64 {
    const NOISE_M: f64 = 5.0;
    let mut total = 0.0;
    let mut base: Option<f64> = None;
    for ele in points.iter().filter_map(|p| p.2) {
        match base {
            None => base = Some(ele),
            Some(b) if ele > b + NOISE_M => {
                total += ele - b;
                base = Some(ele);
            }
            Some(b) if ele < b => base = Some(ele),
            _ => {}
        }
    }
    total
}

const MONTHS: [&str; 12] = [
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
];

/// "June 2024" from an ISO 8601 time such as "2024-06-12T09:15:02Z".
fn month_year(iso: &str) -> Option<String> {
    let year: u32 = iso.get(0..4)?.parse().ok()?;
    let month: usize = iso.get(5..7)?.parse().ok()?;
    Some(format!("{} {year}", MONTHS.get(month.checked_sub(1)?)?))
}

/// Words for an activity, so a query in plain words finds it: "Biking" and
/// "cycling" both say bike ride.
fn activity_words(activity: &str) -> &'static str {
    let a = activity.to_ascii_lowercase();
    if ["bik", "cycl", "ride", "mtb", "gravel"]
        .iter()
        .any(|w| a.contains(w))
    {
        "bike ride cycling"
    } else if a.contains("run") {
        "run running"
    } else if ["hik", "walk", "trek"].iter().any(|w| a.contains(w)) {
        "hike walk"
    } else {
        ""
    }
}

impl Track {
    /// The text search finds this track by.
    pub fn text(&self) -> String {
        let mut out = Vec::new();
        out.push(
            match self.kind {
                TrackKind::Route => "GPS route, planned route",
                TrackKind::Recorded => "GPS track, recorded activity",
            }
            .to_string(),
        );
        if let Some(a) = &self.activity {
            out.push(format!("{a} {}", activity_words(a)));
        }
        if let Some(when) = self.start.as_deref().and_then(month_year) {
            out.push(when);
        }
        out.extend(self.texts.iter().cloned());
        if self.distance_m > 0.0 {
            out.push(format!("{:.0} km", self.distance_m / 1000.0));
        }
        if self.climb_m > 0.0 {
            out.push(format!("{:.0} m climbing", self.climb_m));
        }
        out.join("\n")
    }
}

/// How far apart the points are that `places` looks up.
const PLACE_EVERY_M: f64 = 2_000.0;

/// Milliseconds since the Unix epoch, from an ISO 8601 time such as
/// "2024-06-12T09:15:02Z", "2024-06-12T09:15:02.5+02:00", or a date alone
/// (midnight, UTC). `None` for anything else.
pub fn iso_ms(iso: &str) -> Option<u64> {
    let num = |s: &str| -> Option<i64> { s.parse().ok() };
    let y = num(iso.get(0..4)?)?;
    let mo = num(iso.get(5..7)?)?;
    let d = num(iso.get(8..10)?)?;
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) {
        return None;
    }
    let (mut secs, rest) = match iso.get(10..11) {
        Some("T" | " ") => {
            let h = num(iso.get(11..13)?)?;
            let mi = num(iso.get(14..16)?)?;
            let s = num(iso.get(17..19)?)?;
            (h * 3600 + mi * 60 + s, iso.get(19..).unwrap_or(""))
        }
        _ => (0, ""),
    };
    // Days from 1970-01-01 to the date (Howard Hinnant's days_from_civil).
    let yy = if mo <= 2 { y - 1 } else { y };
    let era = yy.div_euclid(400);
    let yoe = yy - era * 400;
    let mp = (mo + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let rest = rest.trim_start_matches(|c: char| c == '.' || c.is_ascii_digit());
    if let Some(sign) = rest.chars().next().filter(|c| *c == '+' || *c == '-') {
        let h = num(rest.get(1..3)?)?;
        let m = num(rest.get(rest.len().saturating_sub(2)..)?).unwrap_or(0);
        let offset = h * 3600 + m * 60;
        secs -= if sign == '+' { offset } else { -offset };
    }
    u64::try_from((days * 86_400 + secs) * 1000).ok()
}

impl Track {
    /// The names of where the track goes: its points every
    /// `PLACE_EVERY_M`, and its start and end, looked up in `places`.
    /// Towns in the order the track meets them, then regions, then
    /// countries; each once.
    pub fn place_names(&self, places: &Places) -> Vec<String> {
        let mut samples = Vec::new();
        let mut since = f64::INFINITY;
        for w in self.points.windows(2) {
            if since >= PLACE_EVERY_M {
                samples.push((w[0].0, w[0].1));
                since = 0.0;
            }
            since += haversine((w[0].0, w[0].1), (w[1].0, w[1].1));
        }
        if let Some(&(lat, lon, _)) = self.points.last() {
            samples.push((lat, lon));
        }
        let (mut towns, mut regions, mut countries) = (Vec::new(), Vec::new(), Vec::new());
        let add = |list: &mut Vec<String>, name: Option<String>| {
            if let Some(n) = name
                && !list.contains(&n)
            {
                list.push(n);
            }
        };
        for (lat, lon) in samples {
            let p = places.locate(lat, lon);
            add(&mut towns, p.town);
            add(&mut regions, p.region);
            add(&mut regions, p.region_local);
            add(&mut countries, p.country);
        }
        towns.into_iter().chain(regions).chain(countries).collect()
    }

    /// The track as raft5fs-search indexes it: its text, with its places
    /// if `places` is given, and its facts.
    pub fn extracted(&self, places: Option<&Places>) -> Extracted {
        let mut text = self.text();
        if let Some(places) = places {
            let names = self.place_names(places);
            if !names.is_empty() {
                text.push_str("\nPlaces: ");
                text.push_str(&names.join(", "));
            }
        }
        let units = |deg: f64| (deg * 1e4).round() as i32;
        Extracted {
            kind: DocKind::Track,
            text,
            extra: Extra {
                reader: READER,
                when_ms: self.start.as_deref().and_then(iso_ms).unwrap_or(0),
                at: self.points.first().map(|p| (units(p.0), units(p.1))),
                distance_m: self.distance_m.round() as u32,
                climb_m: self.climb_m.round() as u32,
                ..Extra::default()
            },
            thumb: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GPX: &str = r#"<?xml version="1.0"?>
<gpx version="1.1" xmlns="http://www.topografix.com/GPX/1/1">
  <metadata><name>Kingdom loop</name><time>2024-06-12T09:00:00Z</time></metadata>
  <wpt lat="44.6" lon="-71.9"><name>Darling Hill</name></wpt>
  <trk><name>Kingdom Trails 40k</name><desc>Gravel &amp; singletrack</desc><type>cycling</type>
    <trkseg>
      <trkpt lat="44.5000" lon="-72.0000"><ele>300</ele><time>2024-06-12T09:15:02Z</time></trkpt>
      <trkpt lat="44.5090" lon="-72.0000"><ele>302</ele></trkpt>
      <trkpt lat="44.5180" lon="-72.0000"><ele>340</ele></trkpt>
      <trkpt lat="44.5270" lon="-72.0000"><ele>320</ele></trkpt>
    </trkseg>
  </trk>
</gpx>"#;

    /// The same ride as `GPX`, as TCX.
    const TCX: &str = r#"<?xml version="1.0"?>
<TrainingCenterDatabase xmlns="http://www.garmin.com/xmlschemas/TrainingCenterDatabase/v2">
  <Activities><Activity Sport="Biking">
    <Id>2024-06-12T09:15:02Z</Id>
    <Lap StartTime="2024-06-12T09:15:02Z"><DistanceMeters>3002.0</DistanceMeters>
      <Track>
        <Trackpoint><Position><LatitudeDegrees>44.5000</LatitudeDegrees><LongitudeDegrees>-72.0000</LongitudeDegrees></Position><AltitudeMeters>300</AltitudeMeters></Trackpoint>
        <Trackpoint><Position><LatitudeDegrees>44.5090</LatitudeDegrees><LongitudeDegrees>-72.0000</LongitudeDegrees></Position><AltitudeMeters>302</AltitudeMeters></Trackpoint>
        <Trackpoint><Position><LatitudeDegrees>44.5180</LatitudeDegrees><LongitudeDegrees>-72.0000</LongitudeDegrees></Position><AltitudeMeters>340</AltitudeMeters></Trackpoint>
        <Trackpoint><Position><LatitudeDegrees>44.5270</LatitudeDegrees><LongitudeDegrees>-72.0000</LongitudeDegrees></Position><AltitudeMeters>320</AltitudeMeters></Trackpoint>
      </Track>
      <Notes>Kingdom Trails 40k</Notes>
    </Lap>
  </Activity></Activities>
</TrainingCenterDatabase>"#;

    #[test]
    fn a_gpx_track_gives_names_activity_and_numbers() {
        let t = parse_gpx(GPX.as_bytes()).unwrap();
        assert_eq!(t.kind, TrackKind::Recorded);
        assert_eq!(t.activity.as_deref(), Some("cycling"));
        assert_eq!(t.points.len(), 4);
        // Three steps of 0.009 degrees of latitude: about 1 km each.
        assert!((t.distance_m - 3002.0).abs() < 5.0, "{}", t.distance_m);
        // 300 → 302 is noise; 302 → 340 is a climb (from the low of 300).
        assert_eq!(t.climb_m, 40.0);
        let text = t.text();
        for want in [
            "Kingdom Trails 40k",
            "Gravel & singletrack",
            "Darling Hill",
            "bike ride",
            "June 2024",
            "3 km",
        ] {
            assert!(text.contains(want), "{want} in {text}");
        }
    }

    #[test]
    fn a_tcx_activity_matches_the_same_ride_as_gpx() {
        let g = parse_gpx(GPX.as_bytes()).unwrap();
        let t = parse_tcx(TCX.as_bytes()).unwrap();
        assert_eq!(t.kind, TrackKind::Recorded);
        assert_eq!(t.activity.as_deref(), Some("Biking"));
        assert_eq!(t.start.as_deref(), Some("2024-06-12T09:15:02Z"));
        assert_eq!(t.points.len(), g.points.len());
        assert!((t.distance_m - g.distance_m).abs() / g.distance_m < 0.01);
        assert_eq!(t.climb_m, g.climb_m);
        assert!(t.text().contains("bike ride") && t.text().contains("June 2024"));
    }

    #[test]
    fn routes_are_routes() {
        let gpx = r#"<gpx><rte><name>Lake loop</name><rtept lat="1" lon="2"/><rtept lat="1.01" lon="2"/></rte></gpx>"#;
        let t = parse_gpx(gpx.as_bytes()).unwrap();
        assert_eq!(t.kind, TrackKind::Route);
        assert!(t.text().starts_with("GPS route"));
        let tcx = r#"<TrainingCenterDatabase><Courses><Course><Name>Gap ride</Name>
            <Track><Trackpoint><Position><LatitudeDegrees>1</LatitudeDegrees><LongitudeDegrees>2</LongitudeDegrees></Position></Trackpoint></Track>
            <CoursePoint><Name>Summit</Name></CoursePoint></Course></Courses></TrainingCenterDatabase>"#;
        let t = parse_tcx(tcx.as_bytes()).unwrap();
        assert_eq!(t.kind, TrackKind::Route);
        assert_eq!(t.texts, ["Gap ride", "Summit"]);
        assert_eq!(t.points.len(), 1);
    }

    #[test]
    fn bad_xml_gives_none() {
        assert!(parse_gpx(b"<gpx><trk></gpx>").is_none());
        assert!(parse_tcx(b"<a").is_none());
    }

    #[test]
    fn months_and_activities_read_plainly() {
        assert_eq!(month_year("2023-12-01").as_deref(), Some("December 2023"));
        assert_eq!(month_year("2023-13-01"), None);
        assert_eq!(month_year("x"), None);
        assert_eq!(activity_words("MountainBiking"), "bike ride cycling");
        assert_eq!(activity_words("Running"), "run running");
        assert_eq!(activity_words("Other"), "");
    }

    fn real_places() -> Places {
        Places::decode(include_bytes!("../../data/places.bin")).unwrap()
    }

    /// A GPX ride along `points` (latitude, longitude), as Ride with GPS
    /// exports one.
    fn ride(name: &str, points: &[(f64, f64)]) -> String {
        let pts: String = points
            .iter()
            .map(|(la, lo)| format!(r#"<trkpt lat="{la}" lon="{lo}"><ele>200</ele></trkpt>"#))
            .collect();
        format!(
            r#"<gpx><trk><name>{name}</name><type>cycling</type><trkseg>{pts}</trkseg></trk></gpx>"#
        )
    }

    /// Points from `a` to `b`, about every 500 m.
    fn line(a: (f64, f64), b: (f64, f64)) -> Vec<(f64, f64)> {
        let n = (haversine(a, b) / 500.0).ceil() as usize;
        (0..=n)
            .map(|i| {
                let t = i as f64 / n as f64;
                (a.0 + (b.0 - a.0) * t, a.1 + (b.1 - a.1) * t)
            })
            .collect()
    }

    #[test]
    fn a_vermont_ride_names_its_towns_and_state() {
        let places = real_places();
        // Lyndonville to St. Johnsbury, Vermont.
        let gpx = ride(
            "Morning loop",
            &line((44.5361, -72.0053), (44.4192, -72.0151)),
        );
        let got = parse_gpx(gpx.as_bytes()).unwrap().extracted(Some(&places));
        assert!(got.text.contains("Lyndonville"), "{}", got.text);
        assert!(
            got.text.contains("Saint Johnsbury") || got.text.contains("St. Johnsbury"),
            "{}",
            got.text
        );
        assert!(
            got.text.contains("Vermont") && got.text.contains("United States"),
            "{}",
            got.text
        );
        assert!(!got.text.contains("New Hampshire"), "{}", got.text);
        assert_eq!(got.extra.at, Some((445_361, -720_053)));
        assert!(
            (12_000..14_500).contains(&got.extra.distance_m),
            "{}",
            got.extra.distance_m
        );
    }

    #[test]
    fn a_route_over_the_border_names_both_states() {
        let places = real_places();
        // Norwich, Vermont, over the Connecticut River to Hanover, New
        // Hampshire.
        let gpx = ride(
            "River crossing",
            &line((43.7153, -72.3079), (43.7022, -72.2896)),
        );
        let names = parse_gpx(gpx.as_bytes()).unwrap().place_names(&places);
        let vt = names.iter().position(|n| n == "Vermont");
        let nh = names.iter().position(|n| n == "New Hampshire");
        assert!(vt.is_some() && nh.is_some(), "{names:?}");
        assert!(vt < nh, "in the order the route meets them: {names:?}");
    }

    #[test]
    fn tcx_and_gpx_of_one_ride_name_the_same_places() {
        let places = real_places();
        let g = parse_gpx(GPX.as_bytes()).unwrap();
        let t = parse_tcx(TCX.as_bytes()).unwrap();
        assert_eq!(g.place_names(&places), t.place_names(&places));
        assert!(g.place_names(&places).contains(&"Vermont".to_string()));
        let (ge, te) = (g.extracted(Some(&places)), t.extracted(Some(&places)));
        assert_eq!(te.extra.when_ms, iso_ms("2024-06-12T09:15:02Z").unwrap());
        assert_eq!(ge.extra.climb_m, te.extra.climb_m);
    }

    #[test]
    fn bike_routes_in_vermont_finds_the_vermont_ride_first() {
        use crate::record::{Entry, Record, Stamp};
        use crate::view::View;
        let places = real_places();
        let doc = |ino: u64, path: &str, gpx: String| {
            let ex = parse_gpx(gpx.as_bytes()).unwrap().extracted(Some(&places));
            Entry::Record(Record {
                ino,
                at_ms: 1,
                stamp: Stamp {
                    mtime_ns: 1,
                    size: 1,
                },
                path: path.into(),
                kind: ex.kind,
                model: String::new(),
                chunks: crate::text::chunks(&ex.text),
                extra: ex.extra,
            })
        };
        let view = View::new([
            doc(
                1,
                "rides/a.gpx",
                ride("Lake loop", &line((44.4759, -73.2121), (44.55, -73.2))),
            ),
            doc(
                2,
                "rides/b.gpx",
                ride("Coast ride", &line((41.6, -70.6), (41.7, -70.5))),
            ),
        ]);
        let hits = view.search("bike routes in vermont", 5);
        assert_eq!(hits.first().map(|h| h.ino), Some(1), "{hits:?}");
    }

    #[test]
    fn iso_times_read_with_their_offsets() {
        assert_eq!(iso_ms("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(iso_ms("2024-06-12T09:15:02Z"), Some(1_718_183_702_000));
        assert_eq!(
            iso_ms("2024-06-12T11:15:02.250+02:00"),
            Some(1_718_183_702_000)
        );
        assert_eq!(iso_ms("2024-06-12"), Some(1_718_150_400_000));
        assert_eq!(iso_ms("June"), None);
        assert_eq!(iso_ms("2024-13-01"), None);
    }
}
