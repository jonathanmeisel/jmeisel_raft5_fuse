//! Filters: which files a search may return, by their facts. A filter is
//! a list of terms, written as `key:value` words in a query:
//!
//! - `type:photo`, `activity:ride`, `taken:2024-06..2024-09`,
//!   `added:2026-03..`, `modified:..2020`, `place:PT`, `place:"New York"`,
//!   `near:38.72,-9.14,25km`, `by:alice`, `size:>10MB`, `length:<5min`,
//!   `pages:>10`, `distance:>50km`, `climb:>1000m`, `camera:iphone`,
//!   `shape:portrait`, `is:selfie`, `in:taxes` (a folder),
//!   `volume:CS101/alice`, and `sort:newest` or `sort:oldest`.
//! - `-` before a term excludes what it matches: `-type:pdf`.
//! - Terms of one key match if any of them does (`type:photo type:video`);
//!   terms of different keys must all match. An excluding term must not.
//! - Words that aren't terms are the query's text.
//!
//! Dates are days in the searcher's time zone (`Filter::offset_ms`); a
//! range includes both ends. `taken` falls back to the modified time for a
//! file with no date of its own, and so does `added`.

use std::fmt;

use unicode_normalization::UnicodeNormalization;

use crate::generation::Row;
use crate::record::{Activity, DocKind, Meta, Record, Stamp};

/// What sort of file it is, finer than `DocKind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileType {
    Photo,
    Screenshot,
    Video,
    Audio,
    Pdf,
    Document,
    Spreadsheet,
    Presentation,
    Track,
    Archive,
    Code,
    Other,
}

const IMAGE: &[&str] = &[
    "jpg", "jpeg", "heic", "heif", "png", "webp", "tif", "tiff", "gif", "bmp", "avif", "dng",
    "cr2", "cr3", "nef", "arw", "raf", "orf",
];
const VIDEO: &[&str] = &[
    "mp4", "mov", "m4v", "3gp", "mkv", "webm", "avi", "wmv", "mpg", "mpeg", "mts",
];
const AUDIO: &[&str] = &[
    "mp3", "m4a", "aac", "flac", "ogg", "oga", "opus", "wav", "wma", "aif", "aiff",
];
const DOCUMENT: &[&str] = &[
    "txt", "md", "markdown", "rtf", "doc", "docx", "odt", "html", "htm", "pages", "tex", "epub",
    "org", "rst",
];
const SPREADSHEET: &[&str] = &["xls", "xlsx", "ods", "csv", "tsv", "numbers"];
const PRESENTATION: &[&str] = &["ppt", "pptx", "odp", "key"];
const TRACK: &[&str] = &["gpx", "tcx", "fit", "kml"];
const ARCHIVE: &[&str] = &["zip", "tar", "gz", "tgz", "7z", "rar", "bz2", "xz", "zst"];
const CODE: &[&str] = &[
    "rs", "py", "js", "ts", "go", "c", "h", "cc", "cpp", "hpp", "java", "kt", "rb", "sh", "json",
    "yaml", "yml", "toml", "css", "sql", "swift", "php", "lua", "ipynb",
];
/// Words in a screenshot's name, as phones and computers name them.
const SCREENSHOT_NAMES: &[&str] = &["screenshot", "screen shot", "bildschirmfoto", "captura"];

impl FileType {
    pub const ALL: [FileType; 12] = [
        FileType::Photo,
        FileType::Screenshot,
        FileType::Video,
        FileType::Audio,
        FileType::Pdf,
        FileType::Document,
        FileType::Spreadsheet,
        FileType::Presentation,
        FileType::Track,
        FileType::Archive,
        FileType::Code,
        FileType::Other,
    ];

    /// Its name in the syntax.
    pub fn name(self) -> &'static str {
        match self {
            FileType::Photo => "photo",
            FileType::Screenshot => "screenshot",
            FileType::Video => "video",
            FileType::Audio => "audio",
            FileType::Pdf => "pdf",
            FileType::Document => "document",
            FileType::Spreadsheet => "spreadsheet",
            FileType::Presentation => "presentation",
            FileType::Track => "track",
            FileType::Archive => "archive",
            FileType::Code => "code",
            FileType::Other => "other",
        }
    }

    /// What a chip calls it.
    pub fn label(self) -> &'static str {
        match self {
            FileType::Photo => "Photos",
            FileType::Screenshot => "Screenshots",
            FileType::Video => "Videos",
            FileType::Audio => "Audio",
            FileType::Pdf => "PDFs",
            FileType::Document => "Documents",
            FileType::Spreadsheet => "Spreadsheets",
            FileType::Presentation => "Presentations",
            FileType::Track => "GPS tracks",
            FileType::Archive => "Archives",
            FileType::Code => "Code",
            FileType::Other => "Other files",
        }
    }

    pub fn of_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|t| t.name() == name)
    }

    /// The type of a file with these facts.
    pub fn of(f: &Facts<'_>) -> Self {
        let name = f.path.rsplit('/').next().unwrap_or(f.path);
        let ext = name
            .rsplit_once('.')
            .map(|(_, e)| e.to_ascii_lowercase())
            .unwrap_or_default();
        let ext = ext.as_str();
        let image = f.kind == DocKind::Photo || IMAGE.contains(&ext);
        if image {
            let lower = name.to_lowercase();
            let named = SCREENSHOT_NAMES.iter().any(|w| lower.contains(w));
            // A PNG with nothing a camera writes is most likely a capture.
            let bare = ext == "png" && f.meta.camera.is_empty() && f.at.is_none() && f.when_ms == 0;
            return if named || bare {
                FileType::Screenshot
            } else {
                FileType::Photo
            };
        }
        if f.kind == DocKind::Track || TRACK.contains(&ext) {
            return FileType::Track;
        }
        match f.kind {
            DocKind::Video => return FileType::Video,
            DocKind::Audio => return FileType::Audio,
            _ => {}
        }
        let lists: [(&[&str], FileType); 7] = [
            (VIDEO, FileType::Video),
            (AUDIO, FileType::Audio),
            (DOCUMENT, FileType::Document),
            (SPREADSHEET, FileType::Spreadsheet),
            (PRESENTATION, FileType::Presentation),
            (ARCHIVE, FileType::Archive),
            (CODE, FileType::Code),
        ];
        if ext == "pdf" {
            return FileType::Pdf;
        }
        lists
            .into_iter()
            .find(|(l, _)| l.contains(&ext))
            .map_or(FileType::Other, |(_, t)| t)
    }
}

/// A file's facts, from a generation's row or a recent record.
#[derive(Debug, Clone, Copy)]
pub struct Facts<'a> {
    pub path: &'a str,
    pub kind: DocKind,
    pub stamp: Stamp,
    pub when_ms: u64,
    pub at: Option<(i32, i32)>,
    pub distance_m: u32,
    pub climb_m: u32,
    pub meta: &'a Meta,
}

impl<'a> Facts<'a> {
    pub fn of_row(r: &'a Row) -> Self {
        Self {
            path: &r.path,
            kind: r.kind,
            stamp: r.stamp,
            when_ms: r.when_ms,
            at: r.at,
            distance_m: r.distance_m,
            climb_m: r.climb_m,
            meta: &r.meta,
        }
    }

    pub fn of_record(r: &'a Record) -> Self {
        Self {
            path: &r.path,
            kind: r.kind,
            stamp: r.stamp,
            when_ms: r.extra.when_ms,
            at: r.extra.at,
            distance_m: r.extra.distance_m,
            climb_m: r.extra.climb_m,
            meta: &r.extra.meta,
        }
    }

    /// `self`, at `path` (a file moved since its row was written).
    pub fn at_path(self, path: &'a str) -> Self {
        Self { path, ..self }
    }

    fn modified_ms(&self) -> u64 {
        self.stamp.mtime_ns / 1_000_000
    }

    /// When it was taken or recorded, else when it was last changed.
    pub fn taken_ms(&self) -> u64 {
        if self.when_ms > 0 {
            self.when_ms
        } else {
            self.modified_ms()
        }
    }

    fn added_ms(&self) -> u64 {
        if self.meta.added_ms > 0 {
            self.meta.added_ms
        } else {
            self.modified_ms()
        }
    }
}

/// A day, a month or a year: `2024`, `2024-06` or `2024-06-12`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Day {
    pub year: i32,
    pub month: Option<u32>,
    pub day: Option<u32>,
}

impl Day {
    pub fn year(year: i32) -> Self {
        Self {
            year,
            month: None,
            day: None,
        }
    }

    pub fn month(year: i32, month: u32) -> Self {
        Self {
            year,
            month: Some(month),
            day: None,
        }
    }

    pub fn ymd(year: i32, month: u32, day: u32) -> Self {
        Self {
            year,
            month: Some(month),
            day: Some(day),
        }
    }

    /// The first day it covers, as days since 1970-01-01.
    pub fn first(&self) -> i64 {
        days_from_civil(self.year, self.month.unwrap_or(1), self.day.unwrap_or(1))
    }

    /// The day after the last it covers, as days since 1970-01-01.
    pub fn after(&self) -> i64 {
        match (self.month, self.day) {
            (Some(m), Some(d)) => days_from_civil(self.year, m, d) + 1,
            (Some(12), None) => days_from_civil(self.year + 1, 1, 1),
            (Some(m), None) => days_from_civil(self.year, m + 1, 1),
            (None, _) => days_from_civil(self.year + 1, 1, 1),
        }
    }

    fn parse(s: &str) -> Option<Self> {
        let mut parts = s.split('-');
        let year: i32 = parts.next()?.parse().ok()?;
        let month: Option<u32> = parts.next().map(str::parse).transpose().ok()?;
        let day: Option<u32> = parts.next().map(str::parse).transpose().ok()?;
        if parts.next().is_some()
            || !(1..=9999).contains(&year)
            || month.is_some_and(|m| !(1..=12).contains(&m))
            || day.is_some_and(|d| !(1..=31).contains(&d))
        {
            return None;
        }
        Some(Self { year, month, day })
    }
}

impl fmt::Display for Day {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:04}", self.year)?;
        if let Some(m) = self.month {
            write!(f, "-{m:02}")?;
        }
        if let Some(d) = self.day {
            write!(f, "-{d:02}")?;
        }
        Ok(())
    }
}

/// Days since 1970-01-01 (Howard Hinnant's days_from_civil).
pub const fn days_from_civil(y: i32, m: u32, d: u32) -> i64 {
    let (y, m, d) = (y as i64, m as i64, d as i64);
    let yy = if m <= 2 { y - 1 } else { y };
    let era = yy.div_euclid(400);
    let yoe = yy - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The date (year, month, day) of a day since 1970-01-01.
pub fn civil_from_days(z: i64) -> (i32, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    ((if m <= 2 { y + 1 } else { y }) as i32, m, d)
}

/// Days from `from` to `to`, both ends included; either end open.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Dates {
    pub from: Option<Day>,
    pub to: Option<Day>,
}

impl Dates {
    fn keeps(&self, ms: u64, offset_ms: i64) -> bool {
        let day = (ms as i64 + offset_ms).div_euclid(86_400_000);
        self.from.is_none_or(|f| day >= f.first()) && self.to.is_none_or(|t| day < t.after())
    }
}

impl fmt::Display for Dates {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.from, self.to) {
            (Some(a), Some(b)) if a == b => write!(f, "{a}"),
            (Some(a), Some(b)) => write!(f, "{a}..{b}"),
            (Some(a), None) => write!(f, "{a}.."),
            (None, Some(b)) => write!(f, "..{b}"),
            (None, None) => write!(f, ".."),
        }
    }
}

/// A number from `from` to `to`, both included; either end open.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Range {
    pub from: Option<u64>,
    pub to: Option<u64>,
}

impl Range {
    pub fn keeps(&self, n: u64) -> bool {
        self.from.is_none_or(|f| n >= f) && self.to.is_none_or(|t| n <= t)
    }
}

/// The units a range's numbers are written in, smallest first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Measure {
    /// Bytes.
    Size,
    /// Milliseconds.
    Length,
    Pages,
    /// Metres.
    Distance,
    /// Metres.
    Climb,
}

impl Measure {
    /// Each unit's names and its size in the measure's base.
    fn units(self) -> &'static [(&'static str, u64)] {
        match self {
            Measure::Size => &[
                ("b", 1),
                ("kb", 1 << 10),
                ("mb", 1 << 20),
                ("gb", 1 << 30),
                ("tb", 1 << 40),
            ],
            Measure::Length => &[
                ("ms", 1),
                ("s", 1000),
                ("sec", 1000),
                ("min", 60_000),
                ("h", 3_600_000),
                ("hr", 3_600_000),
            ],
            Measure::Pages => &[("", 1)],
            Measure::Distance => &[("m", 1), ("km", 1000), ("mi", 1609)],
            Measure::Climb => &[("m", 1), ("ft", 0)],
        }
    }

    /// The unit a number is shown in.
    fn show(self, n: u64) -> String {
        match self {
            Measure::Size => {
                let (unit, size) = [("GB", 1u64 << 30), ("MB", 1 << 20), ("KB", 1 << 10)]
                    .into_iter()
                    .find(|(_, s)| n >= *s && n.is_multiple_of(*s))
                    .unwrap_or(("B", 1));
                format!("{}{unit}", n / size)
            }
            Measure::Length => {
                if n.is_multiple_of(3_600_000) && n > 0 {
                    format!("{}h", n / 3_600_000)
                } else if n.is_multiple_of(60_000) && n > 0 {
                    format!("{}min", n / 60_000)
                } else {
                    format!("{}s", n / 1000)
                }
            }
            Measure::Pages => n.to_string(),
            Measure::Distance => {
                if n.is_multiple_of(1000) && n > 0 {
                    format!("{}km", n / 1000)
                } else {
                    format!("{n}m")
                }
            }
            Measure::Climb => format!("{n}m"),
        }
    }

    /// A number with its unit, such as `10MB`, `1.5h` or `50km`.
    fn parse(self, s: &str) -> Option<u64> {
        let s = s.trim().to_ascii_lowercase();
        let split = s
            .find(|c: char| !(c.is_ascii_digit() || c == '.'))
            .unwrap_or(s.len());
        let (num, unit) = s.split_at(split);
        let num: f64 = num
            .parse()
            .ok()
            .filter(|n: &f64| n.is_finite() && *n >= 0.0)?;
        let unit = unit.trim();
        if self == Measure::Climb && unit == "ft" {
            return Some((num * 0.3048).round() as u64);
        }
        let default = match self {
            Measure::Size => "b",
            Measure::Length => "s",
            Measure::Pages => "",
            Measure::Distance => "km",
            Measure::Climb => "m",
        };
        let unit = if unit.is_empty() { default } else { unit };
        let (_, scale) = self.units().iter().find(|(u, _)| *u == unit)?;
        Some((num * *scale as f64).round() as u64)
    }

    fn range(self, s: &str) -> Option<Range> {
        if let Some(rest) = s.strip_prefix(">=").or_else(|| s.strip_prefix('>')) {
            return Some(Range {
                from: Some(self.parse(rest)?),
                to: None,
            });
        }
        if let Some(rest) = s.strip_prefix("<=").or_else(|| s.strip_prefix('<')) {
            return Some(Range {
                from: None,
                to: Some(self.parse(rest)?),
            });
        }
        if let Some((a, b)) = s.split_once("..") {
            let end = |x: &str| {
                if x.is_empty() {
                    Some(None)
                } else {
                    self.parse(x).map(Some)
                }
            };
            return Some(Range {
                from: end(a)?,
                to: end(b)?,
            });
        }
        let n = self.parse(s)?;
        Some(Range {
            from: Some(n),
            to: Some(n),
        })
    }

    fn write(self, r: &Range, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (r.from, r.to) {
            (Some(a), Some(b)) if a == b => write!(f, "{}", self.show(a)),
            (Some(a), None) => write!(f, ">{}", self.show(a)),
            (None, Some(b)) => write!(f, "<{}", self.show(b)),
            (Some(a), Some(b)) => write!(f, "{}..{}", self.show(a), self.show(b)),
            (None, None) => write!(f, ".."),
        }
    }

    fn key(self) -> &'static str {
        match self {
            Measure::Size => "size",
            Measure::Length => "length",
            Measure::Pages => "pages",
            Measure::Distance => "distance",
            Measure::Climb => "climb",
        }
    }
}

/// A picture's shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Shape {
    Portrait,
    Landscape,
    Square,
    /// At least twice as wide as it is high, or as high as it is wide.
    Panorama,
}

impl Shape {
    const ALL: [Shape; 4] = [
        Shape::Portrait,
        Shape::Landscape,
        Shape::Square,
        Shape::Panorama,
    ];

    fn name(self) -> &'static str {
        match self {
            Shape::Portrait => "portrait",
            Shape::Landscape => "landscape",
            Shape::Square => "square",
            Shape::Panorama => "panorama",
        }
    }

    fn keeps(self, w: u32, h: u32) -> bool {
        if w == 0 || h == 0 {
            return false;
        }
        let (w, h) = (f64::from(w), f64::from(h));
        match self {
            Shape::Portrait => h > w * 1.05,
            Shape::Landscape => w > h * 1.05,
            Shape::Square => (w / h - 1.0).abs() <= 0.05,
            Shape::Panorama => w >= h * 2.0 || h >= w * 2.0,
        }
    }
}

fn activity_name(a: Activity) -> &'static str {
    match a {
        Activity::Ride => "ride",
        Activity::Run => "run",
        Activity::Hike => "hike",
        Activity::Walk => "walk",
        Activity::Other => "other",
        Activity::Unknown => "unknown",
    }
}

fn activity_of_name(s: &str) -> Option<Activity> {
    [
        Activity::Ride,
        Activity::Run,
        Activity::Hike,
        Activity::Walk,
        Activity::Other,
    ]
    .into_iter()
    .find(|a| activity_name(*a) == s)
}

/// One condition on a file.
#[derive(Debug, Clone, PartialEq)]
pub enum Clause {
    Type(FileType),
    Activity(Activity),
    Taken(Dates),
    Added(Dates),
    Modified(Dates),
    /// A country code (two capital letters), or a town, region or country
    /// name.
    Place(String),
    /// Within `km` of a point, in degrees.
    Near {
        lat: f64,
        lon: f64,
        km: f64,
    },
    By(String),
    Measure(Measure, Range),
    Camera(String),
    Shape(Shape),
    Selfie,
    /// A folder the file is in.
    In(String),
    /// A volume, by the label it has in the app: the caller chooses the
    /// volumes, so files never fail it.
    Volume(String),
}

impl Clause {
    /// Which clauses join with OR: those of one key.
    pub fn key(&self) -> &'static str {
        match self {
            Clause::Type(_) => "type",
            Clause::Activity(_) => "activity",
            Clause::Taken(_) => "taken",
            Clause::Added(_) => "added",
            Clause::Modified(_) => "modified",
            Clause::Place(_) => "place",
            Clause::Near { .. } => "near",
            Clause::By(_) => "by",
            Clause::Measure(m, _) => m.key(),
            Clause::Camera(_) => "camera",
            Clause::Shape(_) => "shape",
            Clause::Selfie => "is",
            Clause::In(_) => "in",
            Clause::Volume(_) => "volume",
        }
    }

    fn keeps(&self, f: &Facts<'_>, offset_ms: i64) -> bool {
        match self {
            Clause::Type(t) => FileType::of(f) == *t,
            Clause::Activity(a) => f.kind == DocKind::Track && f.meta.activity == *a,
            Clause::Taken(d) => d.keeps(f.taken_ms(), offset_ms),
            Clause::Added(d) => d.keeps(f.added_ms(), offset_ms),
            Clause::Modified(d) => d.keeps(f.modified_ms(), offset_ms),
            Clause::Place(p) => place_keeps(p, f.meta),
            Clause::Near { lat, lon, km } => {
                f.at.map(|(a, o)| (f64::from(a) / 1e4, f64::from(o) / 1e4))
                    .is_some_and(|p| distance_km(p, (*lat, *lon)) <= *km)
            }
            Clause::By(who) => fold(&f.meta.added_by) == fold(who),
            Clause::Measure(m, r) => {
                let n = match m {
                    Measure::Size => f.stamp.size,
                    Measure::Length => f.meta.duration_ms,
                    Measure::Pages => f.meta.pages.into(),
                    Measure::Distance => f.distance_m.into(),
                    Measure::Climb => f.climb_m.into(),
                };
                // An unknown length, page count or distance isn't 0.
                (n > 0 || *m == Measure::Size) && r.keeps(n)
            }
            Clause::Camera(c) => fold(&f.meta.camera).contains(&fold(c)),
            Clause::Shape(s) => s.keeps(f.meta.width, f.meta.height),
            Clause::Selfie => f.meta.selfie,
            Clause::In(folder) => {
                let folder = fold(folder);
                let mut parts: Vec<&str> = f.path.split('/').collect();
                parts.pop();
                parts.into_iter().any(|p| fold(p) == folder)
            }
            Clause::Volume(_) => true,
        }
    }

    /// What a chip says.
    pub fn label(&self) -> String {
        match self {
            Clause::Type(t) => t.label().to_string(),
            Clause::Activity(a) => match a {
                Activity::Ride => "Rides".to_string(),
                Activity::Run => "Runs".to_string(),
                Activity::Hike => "Hikes".to_string(),
                Activity::Walk => "Walks".to_string(),
                _ => "Other activities".to_string(),
            },
            Clause::Taken(d) => format!("Taken {}", dates_label(d)),
            Clause::Added(d) => format!("Added {}", dates_label(d)),
            Clause::Modified(d) => format!("Changed {}", dates_label(d)),
            Clause::Place(p) => p.clone(),
            Clause::Near { km, .. } => format!("Within {km:.0} km"),
            Clause::By(who) => format!("By {who}"),
            Clause::Measure(m, r) => {
                let name = match m {
                    Measure::Size => "Size",
                    Measure::Length => "Length",
                    Measure::Pages => "Pages",
                    Measure::Distance => "Distance",
                    Measure::Climb => "Climb",
                };
                let show = |n: u64| m.show(n);
                let what = match (r.from, r.to) {
                    (Some(a), Some(b)) if a == b => show(a),
                    (Some(a), None) => format!("over {}", show(a)),
                    (None, Some(b)) => format!("under {}", show(b)),
                    (Some(a), Some(b)) => format!("{}–{}", show(a), show(b)),
                    (None, None) => "any".to_string(),
                };
                format!("{name} {what}")
            }
            Clause::Camera(c) => format!("Camera: {c}"),
            Clause::Shape(s) => {
                let n = s.name();
                n[..1].to_uppercase() + &n[1..]
            }
            Clause::Selfie => "Selfies".to_string(),
            Clause::In(f) => format!("In {f}"),
            Clause::Volume(v) => format!("In {v}"),
        }
    }
}

const MONTH_ABBR: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

fn day_label(d: &Day) -> String {
    match (d.month, d.day) {
        (Some(m), Some(day)) => format!("{} {day}, {}", MONTH_ABBR[m as usize - 1], d.year),
        (Some(m), None) => format!("{} {}", MONTH_ABBR[m as usize - 1], d.year),
        _ => d.year.to_string(),
    }
}

fn dates_label(d: &Dates) -> String {
    match (d.from, d.to) {
        (Some(a), Some(b)) if a == b => format!("in {}", day_label(&a)),
        (Some(a), Some(b)) => format!("{} – {}", day_label(&a), day_label(&b)),
        (Some(a), None) => format!("since {}", day_label(&a)),
        (None, Some(b)) => format!("until {}", day_label(&b)),
        (None, None) => "any time".to_string(),
    }
}

/// `s` in lower case without accents, to compare names.
pub fn fold(s: &str) -> String {
    s.nfd()
        .filter(|c| !('\u{300}'..='\u{36f}').contains(c))
        .flat_map(char::to_lowercase)
        .collect()
}

fn is_code(p: &str) -> bool {
    p.len() == 2 && p.chars().all(|c| c.is_ascii_uppercase())
}

fn place_keeps(p: &str, meta: &Meta) -> bool {
    if is_code(p) {
        return meta.places.iter().any(|x| x.code.as_deref() == Some(p));
    }
    let want = fold(p);
    meta.places.iter().any(|x| {
        [&x.town, &x.region, &x.region_local, &x.country]
            .into_iter()
            .flatten()
            .any(|n| fold(n) == want)
    })
}

/// Kilometres between two points, in degrees.
fn distance_km(a: (f64, f64), b: (f64, f64)) -> f64 {
    const R: f64 = 6371.0;
    let (la1, la2) = (a.0.to_radians(), b.0.to_radians());
    let dla = la2 - la1;
    let dlo = (b.1 - a.1).to_radians();
    let h = (dla / 2.0).sin().powi(2) + la1.cos() * la2.cos() * (dlo / 2.0).sin().powi(2);
    2.0 * R * h.sqrt().asin()
}

/// One term of a filter: a clause, or its opposite.
#[derive(Debug, Clone, PartialEq)]
pub struct Term {
    pub clause: Clause,
    pub not: bool,
    /// What its chip says, if not what `Clause::label` gives: the words
    /// the query used ("Taken last summer"), or a country's name.
    pub shown: Option<String>,
}

impl Term {
    /// Its id: how the syntax writes it.
    pub fn id(&self) -> String {
        self.to_string()
    }

    pub fn label(&self) -> String {
        let label = self.shown.clone().unwrap_or_else(|| self.clause.label());
        if self.not {
            format!("Not {label}")
        } else {
            label
        }
    }
}

/// The order of results when a filter asks for one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sort {
    Newest,
    Oldest,
}

/// Which files a search may return.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Filter {
    pub terms: Vec<Term>,
    pub sort: Option<Sort>,
    /// The searcher's offset from UTC, for the days that date terms name.
    pub offset_ms: i64,
}

impl Filter {
    /// Whether it says anything about files.
    pub fn is_empty(&self) -> bool {
        self.terms
            .iter()
            .all(|t| matches!(t.clause, Clause::Volume(_)))
    }

    /// Whether a file with facts `f` passes.
    pub fn keeps(&self, f: &Facts<'_>) -> bool {
        let mut keys: Vec<&str> = Vec::new();
        for t in &self.terms {
            if t.not {
                if t.clause.keeps(f, self.offset_ms) && !matches!(t.clause, Clause::Volume(_)) {
                    return false;
                }
            } else if !keys.contains(&t.clause.key()) {
                keys.push(t.clause.key());
            }
        }
        keys.into_iter().all(|k| {
            self.terms
                .iter()
                .filter(|t| !t.not && t.clause.key() == k)
                .any(|t| t.clause.keeps(f, self.offset_ms))
        })
    }

    /// The volume labels it names: a search covers only these, if any.
    pub fn volumes(&self) -> Vec<&str> {
        self.terms
            .iter()
            .filter(|t| !t.not)
            .filter_map(|t| match &t.clause {
                Clause::Volume(v) => Some(v.as_str()),
                _ => None,
            })
            .collect()
    }

    /// Adds `term` unless one like it is there already.
    pub fn add(&mut self, term: Term) {
        let id = term.id();
        if !self.terms.iter().any(|t| t.id() == id) {
            self.terms.push(term);
        }
    }

    /// `self` without the terms whose ids are in `off`.
    pub fn without(&self, off: &[String]) -> Self {
        Self {
            terms: self
                .terms
                .iter()
                .filter(|t| !off.contains(&t.id()))
                .cloned()
                .collect(),
            ..self.clone()
        }
    }

    /// Splits `query` into the terms it writes and the rest of its words.
    pub fn parse_syntax(query: &str, offset_ms: i64) -> (Self, String) {
        let mut filter = Filter {
            offset_ms,
            ..Filter::default()
        };
        let mut rest = Vec::new();
        for word in words(query) {
            match parse_term(&word) {
                Some(Parsed::Term(t)) => filter.add(t),
                Some(Parsed::Sort(s)) => filter.sort = Some(s),
                None => rest.push(word),
            }
        }
        (filter, rest.join(" "))
    }
}

/// Words of a query, with quoted values kept whole: `place:"New York"`.
fn words(query: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut word = String::new();
    let mut quoted = false;
    for c in query.chars() {
        match c {
            '"' => {
                quoted = !quoted;
                word.push(c);
            }
            c if c.is_whitespace() && !quoted => {
                if !word.is_empty() {
                    out.push(std::mem::take(&mut word));
                }
            }
            c => word.push(c),
        }
    }
    if !word.is_empty() {
        out.push(word);
    }
    out
}

enum Parsed {
    Term(Term),
    Sort(Sort),
}

fn parse_term(word: &str) -> Option<Parsed> {
    let (not, word) = match word.strip_prefix('-') {
        Some(w) => (true, w),
        None => (false, word),
    };
    let (key, value) = word.split_once(':')?;
    let value = value.trim_matches('"');
    if value.is_empty() {
        return None;
    }
    let key = key.to_ascii_lowercase();
    let lower = value.to_ascii_lowercase();
    let dates = || -> Option<Dates> {
        match value.split_once("..") {
            Some((a, b)) => Some(Dates {
                from: if a.is_empty() {
                    None
                } else {
                    Some(Day::parse(a)?)
                },
                to: if b.is_empty() {
                    None
                } else {
                    Some(Day::parse(b)?)
                },
            }),
            None => {
                let d = Day::parse(value)?;
                Some(Dates {
                    from: Some(d),
                    to: Some(d),
                })
            }
        }
    };
    let clause = match key.as_str() {
        "sort" => {
            return match lower.as_str() {
                "newest" if !not => Some(Parsed::Sort(Sort::Newest)),
                "oldest" if !not => Some(Parsed::Sort(Sort::Oldest)),
                _ => None,
            };
        }
        "type" => Clause::Type(FileType::of_name(&lower)?),
        "activity" => Clause::Activity(activity_of_name(&lower)?),
        "taken" => Clause::Taken(dates()?),
        "added" => Clause::Added(dates()?),
        "modified" => Clause::Modified(dates()?),
        "place" => Clause::Place(value.to_string()),
        "near" => {
            let mut parts = value.split(',');
            let lat: f64 = parts.next()?.trim().parse().ok()?;
            let lon: f64 = parts.next()?.trim().parse().ok()?;
            let km = match parts.next() {
                Some(r) => Measure::Distance.parse(r)? as f64 / 1000.0,
                None => 25.0,
            };
            if !(-90.0..=90.0).contains(&lat) || !(-180.0..=180.0).contains(&lon) {
                return None;
            }
            Clause::Near { lat, lon, km }
        }
        "by" => Clause::By(value.to_string()),
        "size" => Clause::Measure(Measure::Size, Measure::Size.range(&lower)?),
        "length" => Clause::Measure(Measure::Length, Measure::Length.range(&lower)?),
        "pages" => Clause::Measure(Measure::Pages, Measure::Pages.range(&lower)?),
        "distance" => Clause::Measure(Measure::Distance, Measure::Distance.range(&lower)?),
        "climb" => Clause::Measure(Measure::Climb, Measure::Climb.range(&lower)?),
        "camera" => Clause::Camera(value.to_string()),
        "shape" => Clause::Shape(Shape::ALL.into_iter().find(|s| s.name() == lower)?),
        "is" if lower == "selfie" => Clause::Selfie,
        "in" => Clause::In(value.to_string()),
        "volume" => Clause::Volume(value.to_string()),
        _ => return None,
    };
    Some(Parsed::Term(Term {
        clause,
        not,
        shown: None,
    }))
}

/// A value as the syntax writes it: quoted if it has spaces.
fn quoted(s: &str) -> String {
    if s.contains(char::is_whitespace) {
        format!("\"{s}\"")
    } else {
        s.to_string()
    }
}

impl fmt::Display for Term {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.not {
            write!(f, "-")?;
        }
        let key = self.clause.key();
        match &self.clause {
            Clause::Type(t) => write!(f, "{key}:{}", t.name()),
            Clause::Activity(a) => write!(f, "{key}:{}", activity_name(*a)),
            Clause::Taken(d) | Clause::Added(d) | Clause::Modified(d) => write!(f, "{key}:{d}"),
            Clause::Place(p) => write!(f, "{key}:{}", quoted(p)),
            Clause::Near { lat, lon, km } => write!(f, "{key}:{lat:.4},{lon:.4},{km}km"),
            Clause::By(s) | Clause::Camera(s) | Clause::In(s) | Clause::Volume(s) => {
                write!(f, "{key}:{}", quoted(s))
            }
            Clause::Measure(m, r) => {
                write!(f, "{key}:")?;
                m.write(r, f)
            }
            Clause::Shape(s) => write!(f, "{key}:{}", s.name()),
            Clause::Selfie => write!(f, "is:selfie"),
        }
    }
}

impl fmt::Display for Filter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for t in &self.terms {
            if !first {
                write!(f, " ")?;
            }
            first = false;
            write!(f, "{t}")?;
        }
        if let Some(s) = self.sort {
            if !first {
                write!(f, " ")?;
            }
            write!(
                f,
                "sort:{}",
                match s {
                    Sort::Newest => "newest",
                    Sort::Oldest => "oldest",
                }
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::geo::Place;

    fn facts_of<'a>(path: &'a str, kind: DocKind, meta: &'a Meta) -> Facts<'a> {
        Facts {
            path,
            kind,
            stamp: Stamp {
                mtime_ns: days_from_civil(2025, 1, 2) as u64 * 86_400_000_000_000,
                size: 5 << 20,
            },
            when_ms: 0,
            at: None,
            distance_m: 0,
            climb_m: 0,
            meta,
        }
    }

    fn filter(s: &str) -> Filter {
        let (f, rest) = Filter::parse_syntax(s, 0);
        assert_eq!(rest, "", "all of {s:?} is terms");
        f
    }

    #[test]
    fn types_come_from_kinds_names_and_facts() {
        let none = Meta::default();
        let camera = Meta {
            camera: "Apple iPhone 13".into(),
            ..Meta::default()
        };
        let ty = |p, k, m| FileType::of(&facts_of(p, k, m));
        assert_eq!(ty("a/b.jpg", DocKind::Photo, &camera), FileType::Photo);
        assert_eq!(ty("a/b.HEIC", DocKind::Opaque, &none), FileType::Photo);
        assert_eq!(
            ty("Screenshot 2024.png", DocKind::Photo, &camera),
            FileType::Screenshot
        );
        assert_eq!(
            ty("diagram.png", DocKind::Photo, &none),
            FileType::Screenshot
        );
        assert_eq!(ty("clip.MOV", DocKind::Opaque, &none), FileType::Video);
        assert_eq!(ty("song.mp3", DocKind::Opaque, &none), FileType::Audio);
        assert_eq!(ty("tax.pdf", DocKind::Text, &none), FileType::Pdf);
        assert_eq!(ty("notes.md", DocKind::Text, &none), FileType::Document);
        assert_eq!(
            ty("budget.xlsx", DocKind::Text, &none),
            FileType::Spreadsheet
        );
        assert_eq!(ty("ride.gpx", DocKind::Track, &none), FileType::Track);
        assert_eq!(ty("x.tar.gz", DocKind::Opaque, &none), FileType::Archive);
        assert_eq!(ty("main.rs", DocKind::Text, &none), FileType::Code);
        assert_eq!(ty("README", DocKind::Text, &none), FileType::Other);
    }

    #[test]
    fn terms_of_a_key_join_with_or_and_keys_with_and() {
        let meta = Meta::default();
        let pdf = facts_of("tax.pdf", DocKind::Text, &meta);
        let jpg = facts_of("a.jpg", DocKind::Photo, &meta);
        let f = filter("type:pdf type:photo");
        assert!(f.keeps(&pdf) && f.keeps(&jpg));
        let f = filter("type:pdf size:<1MB");
        assert!(!f.keeps(&pdf), "5 MB is over");
        let f = filter("type:pdf size:>1MB");
        assert!(f.keeps(&pdf) && !f.keeps(&jpg));
        let f = filter("-type:pdf");
        assert!(!f.keeps(&pdf) && f.keeps(&jpg));
        assert!(Filter::default().keeps(&pdf), "no terms keep all");
    }

    #[test]
    fn dates_cover_whole_days_months_and_years() {
        let meta = Meta::default();
        // Modified 2025-01-02; no date of its own, so taken falls back.
        let f = facts_of("a.txt", DocKind::Text, &meta);
        for yes in [
            "taken:2025",
            "taken:2025-01",
            "taken:2025-01-02",
            "modified:2024..2025",
            "added:..2025-01-02",
            "taken:2025-01-02..",
        ] {
            assert!(filter(yes).keeps(&f), "{yes}");
        }
        for no in ["taken:2024", "taken:2025-01-03..", "modified:..2025-01-01"] {
            assert!(!filter(no).keeps(&f), "{no}");
        }
        // Late on the 1st in UTC is the 2nd five hours east.
        let late = Facts {
            when_ms: (days_from_civil(2025, 1, 1) * 86_400_000 + 22 * 3_600_000) as u64,
            ..f
        };
        let (east, _) = Filter::parse_syntax("taken:2025-01-02", 5 * 3_600_000);
        assert!(east.keeps(&late) && !filter("taken:2025-01-02").keeps(&late));
    }

    #[test]
    fn places_match_by_code_or_any_name_without_accents() {
        let meta = Meta {
            places: vec![Place {
                town: Some("São Paulo".into()),
                region: Some("Sao Paulo".into()),
                region_local: None,
                country: Some("Brazil".into()),
                code: Some("BR".into()),
            }],
            ..Meta::default()
        };
        let f = facts_of("a.jpg", DocKind::Photo, &meta);
        for yes in [
            "place:BR",
            "place:brazil",
            "place:\"sao paulo\"",
            "place:\"São Paulo\"",
        ] {
            assert!(filter(yes).keeps(&f), "{yes}");
        }
        assert!(!filter("place:PT").keeps(&f));
        assert!(!filter("place:paulo").keeps(&f), "whole names only");
    }

    #[test]
    fn near_measures_who_and_what() {
        let meta = Meta {
            added_by: "Alice".into(),
            camera: "Apple iPhone 13".into(),
            width: 3024,
            height: 4032,
            selfie: true,
            pages: 0,
            duration_ms: 90 * 60_000,
            ..Meta::default()
        };
        let mut f = facts_of("trips/2024/a.jpg", DocKind::Photo, &meta);
        f.at = Some((387_223, -91_393));
        for yes in [
            "near:38.7,-9.1,10km",
            "by:alice",
            "camera:iphone",
            "shape:portrait",
            "is:selfie",
            "in:trips",
            "in:2024",
            "length:>1h",
            "length:1h..2h",
        ] {
            assert!(filter(yes).keeps(&f), "{yes}");
        }
        for no in [
            "near:40.4,-3.7",
            "by:bo",
            "camera:canon",
            "shape:landscape",
            "in:a.jpg",
            "pages:>1",
            "length:<1h",
        ] {
            assert!(!filter(no).keeps(&f), "{no}");
        }
    }

    #[test]
    fn the_syntax_reads_back_as_written() {
        for s in [
            "type:photo",
            "-type:pdf",
            "activity:ride",
            "taken:2024-06..2024-09",
            "added:2026-03..",
            "modified:..2020",
            "taken:2024-06-12",
            "place:PT",
            "place:\"New York\"",
            "near:38.7200,-9.1400,25km",
            "by:alice",
            "size:>10MB",
            "length:<5min",
            "pages:>10",
            "distance:>50km",
            "climb:>1000m",
            "camera:iphone",
            "shape:panorama",
            "is:selfie",
            "in:taxes",
            "volume:CS101/alice",
        ] {
            let f = filter(s);
            assert_eq!(f.terms.len(), 1, "{s}");
            assert_eq!(f.to_string(), s);
            assert_eq!(filter(&f.to_string()), f);
        }
        let (f, rest) = Filter::parse_syntax("tax type:pdf return sort:newest http://x", 0);
        assert_eq!(rest, "tax return http://x");
        assert_eq!(f.to_string(), "type:pdf sort:newest");
        for bad in [
            "type:fish",
            "taken:2024-13",
            "size:big",
            "near:91,0",
            "is:fun",
        ] {
            let (f, rest) = Filter::parse_syntax(bad, 0);
            assert!(f.terms.is_empty(), "{bad}");
            assert_eq!(rest, bad);
        }
    }

    #[test]
    fn units_read_and_show() {
        let r = |m: Measure, s: &str| m.range(s).unwrap();
        assert_eq!(r(Measure::Size, "10mb").from, Some(10 << 20));
        assert_eq!(r(Measure::Size, ">1.5GB").from, Some(1_610_612_736));
        assert_eq!(r(Measure::Length, "<90s").to, Some(90_000));
        assert_eq!(
            r(Measure::Distance, ">50").from,
            Some(50_000),
            "km by default"
        );
        assert_eq!(r(Measure::Distance, ">10mi").from, Some(16_090));
        assert_eq!(r(Measure::Climb, ">1000ft").from, Some(305));
        assert_eq!(
            Term {
                clause: Clause::Measure(Measure::Size, r(Measure::Size, ">10MB")),
                not: false,
                shown: None,
            }
            .label(),
            "Size over 10MB"
        );
    }

    #[test]
    fn civil_days_round_trip() {
        for (y, m, d) in [(1970, 1, 1), (2024, 2, 29), (2026, 11, 27), (1969, 12, 31)] {
            assert_eq!(civil_from_days(days_from_civil(y, m, d)), (y, m, d));
        }
        assert_eq!(Day::month(2024, 12).after(), days_from_civil(2025, 1, 1));
        assert_eq!(Day::year(2024).after(), days_from_civil(2025, 1, 1));
    }

    #[test]
    fn a_term_turned_off_is_left_out_by_its_id() {
        let f = filter("type:photo place:PT -type:pdf");
        let ids: Vec<String> = f.terms.iter().map(Term::id).collect();
        assert_eq!(ids, ["type:photo", "place:PT", "-type:pdf"]);
        let less = f.without(&["place:PT".into(), "-type:pdf".into()]);
        assert_eq!(less.to_string(), "type:photo");
    }

    #[test]
    fn chips_say_what_terms_do() {
        let label = |s: &str| filter(s).terms[0].label();
        assert_eq!(label("type:photo"), "Photos");
        assert_eq!(label("taken:2026-06..2026-09"), "Taken Jun 2026 – Sep 2026");
        assert_eq!(label("taken:2024"), "Taken in 2024");
        assert_eq!(label("added:2026-03.."), "Added since Mar 2026");
        assert_eq!(label("-type:pdf"), "Not PDFs");
        assert_eq!(label("activity:ride"), "Rides");
    }
}
