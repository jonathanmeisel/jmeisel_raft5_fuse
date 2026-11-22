//! GPS tracks and routes: GPX and TCX, read into one `Track`, and the text
//! that search finds a track by.
//!
//! - A GPX `<trk>` and a TCX `<Activity>` are recorded; a GPX `<rte>` and a
//!   TCX `<Course>` are planned routes.
//! - The text has the names, descriptions, the kind of track and activity,
//!   the month it started, its distance and its climbing. Place names from
//!   the points are not added yet.

use quick_xml::events::{BytesStart, Event};
use quick_xml::reader::Reader;

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

pub fn gpx_text(bytes: &[u8]) -> Option<String> {
    Some(parse_gpx(bytes)?.text())
}

pub fn tcx_text(bytes: &[u8]) -> Option<String> {
    Some(parse_tcx(bytes)?.text())
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
}
