//! The words the query rules know, for one language. Only English for
//! now: another language is another `Lexicon`, with the same rules.

use crate::filter::{FileType, Measure, Shape, Sort};
use crate::record::Activity;

use super::DateKind;

/// What a type word asks for.
#[derive(Debug, Clone, Copy)]
pub enum TypeWord {
    Type(FileType),
    Activity(Activity),
    Selfie,
    Shape(Shape),
}

/// What a cue word puts after it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cue {
    /// A place, a volume or a folder.
    In,
    /// A place or a person.
    From,
    Near,
    At,
    By,
    /// A camera.
    With,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compare {
    Over,
    Under,
    Between,
}

pub struct Lexicon {
    /// Type words, longest first.
    pub types: &'static [(&'static [&'static str], TypeWord)],
    /// Cue words, longest first.
    pub cues: &'static [(&'static [&'static str], Cue)],
    pub comparisons: &'static [(&'static [&'static str], Compare)],
    pub sorts: &'static [(&'static [&'static str], Sort)],
    /// Units, with their measure and size in its base unit.
    pub units: &'static [(&'static str, Measure, f64)],
    /// Words after which a type word is what files show or hold: "photos
    /// of documents".
    pub content_cues: &'static [&'static str],
    pub negations: &'static [&'static str],
    /// Words that say a person made the file: "alice uploaded".
    pub added_verbs: &'static [&'static str],
    /// Words that ask for a date other than when taken.
    pub added_dates: &'static [&'static str],
    pub modified_dates: &'static [&'static str],
    /// Words dropped from the text.
    pub filler: &'static [&'static str],
    /// "and", "or": dropped between two terms.
    pub joiners: &'static [&'static str],
    /// Common words, which e5 isn't asked about.
    pub stop: &'static [&'static str],
    /// Place names that are common words too: they need a cue.
    pub common: &'static [&'static str],
    /// Camera makers and phone lines, which name a camera without a cue.
    pub camera_brands: &'static [&'static str],
    /// Type words that are also the first word of a name ("photo
    /// album", "video game"): followed by a plain word, they stay text.
    pub modifiers: &'static [&'static str],
}

impl Lexicon {
    pub fn unit_of(&self, w: &str) -> Option<(Measure, f64)> {
        self.units
            .iter()
            .find(|(u, _, _)| *u == w)
            .map(|(_, m, s)| (*m, *s))
    }

    pub fn is_unit(&self, w: &str) -> bool {
        self.unit_of(w).is_some()
    }

    pub(super) fn date_verbs(&self, w: &str) -> Option<DateKind> {
        if self.added_dates.contains(&w) {
            Some(DateKind::Added)
        } else if self.modified_dates.contains(&w) {
            Some(DateKind::Modified)
        } else {
            None
        }
    }
}

use FileType as F;
use TypeWord::{Activity as A, Type as T};

pub static ENGLISH: Lexicon = Lexicon {
    types: &[
        (&["bike", "rides"], A(Activity::Ride)),
        (&["bike", "ride"], A(Activity::Ride)),
        (&["bike", "routes"], A(Activity::Ride)),
        (&["voice", "memos"], T(F::Audio)),
        (&["voice", "notes"], T(F::Audio)),
        (&["slide", "decks"], T(F::Presentation)),
        (&["gps", "tracks"], T(F::Track)),
        (&["photos"], T(F::Photo)),
        (&["photo"], T(F::Photo)),
        (&["pictures"], T(F::Photo)),
        (&["picture"], T(F::Photo)),
        (&["pics"], T(F::Photo)),
        (&["pic"], T(F::Photo)),
        (&["images"], T(F::Photo)),
        (&["image"], T(F::Photo)),
        (&["snapshots"], T(F::Photo)),
        (&["screenshots"], T(F::Screenshot)),
        (&["screenshot"], T(F::Screenshot)),
        (&["screen", "shots"], T(F::Screenshot)),
        (&["selfies"], TypeWord::Selfie),
        (&["selfie"], TypeWord::Selfie),
        (&["panoramas"], TypeWord::Shape(Shape::Panorama)),
        (&["panorama"], TypeWord::Shape(Shape::Panorama)),
        (&["panoramic"], TypeWord::Shape(Shape::Panorama)),
        (&["vertical"], TypeWord::Shape(Shape::Portrait)),
        (&["horizontal"], TypeWord::Shape(Shape::Landscape)),
        (&["videos"], T(F::Video)),
        (&["video"], T(F::Video)),
        (&["movies"], T(F::Video)),
        (&["clips"], T(F::Video)),
        (&["recordings"], T(F::Audio)),
        (&["recording"], T(F::Audio)),
        (&["audio"], T(F::Audio)),
        (&["songs"], T(F::Audio)),
        (&["music"], T(F::Audio)),
        (&["podcasts"], T(F::Audio)),
        (&["pdfs"], T(F::Pdf)),
        (&["pdf"], T(F::Pdf)),
        (&["documents"], T(F::Document)),
        (&["document"], T(F::Document)),
        (&["docs"], T(F::Document)),
        (&["spreadsheets"], T(F::Spreadsheet)),
        (&["spreadsheet"], T(F::Spreadsheet)),
        (&["presentations"], T(F::Presentation)),
        (&["presentation"], T(F::Presentation)),
        (&["slides"], T(F::Presentation)),
        (&["rides"], A(Activity::Ride)),
        (&["runs"], A(Activity::Run)),
        (&["hikes"], A(Activity::Hike)),
        (&["walks"], A(Activity::Walk)),
        (&["tracks"], T(F::Track)),
        (&["routes"], T(F::Track)),
        (&["gpx"], T(F::Track)),
        (&["archives"], T(F::Archive)),
        (&["zips"], T(F::Archive)),
        (&["zip", "files"], T(F::Archive)),
        (&["code"], T(F::Code)),
        (&["jpgs"], T(F::Photo)),
        (&["jpegs"], T(F::Photo)),
        (&["jpg"], T(F::Photo)),
        (&["heic"], T(F::Photo)),
        (&["mp4s"], T(F::Video)),
        (&["mp3s"], T(F::Audio)),
        (&["docx"], T(F::Document)),
        (&["xlsx"], T(F::Spreadsheet)),
        (&["csvs"], T(F::Spreadsheet)),
    ],
    cues: &[
        (&["taken", "with"], Cue::With),
        (&["taken", "on"], Cue::With),
        (&["shot", "with"], Cue::With),
        (&["shot", "on"], Cue::With),
        (&["taken", "in"], Cue::In),
        (&["taken", "at"], Cue::At),
        (&["added", "by"], Cue::By),
        (&["uploaded", "by"], Cue::By),
        (&["shared", "by"], Cue::By),
        (&["made", "by"], Cue::By),
        (&["created", "by"], Cue::By),
        (&["trip", "to"], Cue::In),
        (&["close", "to"], Cue::Near),
        (&["with", "my"], Cue::With),
        (&["on", "my"], Cue::With),
        (&["in"], Cue::In),
        (&["inside"], Cue::In),
        (&["from"], Cue::From),
        (&["near"], Cue::Near),
        (&["around"], Cue::Near),
        (&["at"], Cue::At),
        (&["by"], Cue::By),
        (&["with"], Cue::With),
    ],
    comparisons: &[
        (&["more", "than"], Compare::Over),
        (&["longer", "than"], Compare::Over),
        (&["bigger", "than"], Compare::Over),
        (&["larger", "than"], Compare::Over),
        (&["greater", "than"], Compare::Over),
        (&["at", "least"], Compare::Over),
        (&["less", "than"], Compare::Under),
        (&["shorter", "than"], Compare::Under),
        (&["smaller", "than"], Compare::Under),
        (&["fewer", "than"], Compare::Under),
        (&["at", "most"], Compare::Under),
        (&["over"], Compare::Over),
        (&["above"], Compare::Over),
        (&[">"], Compare::Over),
        (&["under"], Compare::Under),
        (&["below"], Compare::Under),
        (&["<"], Compare::Under),
        (&["between"], Compare::Between),
    ],
    sorts: &[
        (&["most", "recent"], Sort::Newest),
        (&["newest"], Sort::Newest),
        (&["latest"], Sort::Newest),
        (&["recent"], Sort::Newest),
        (&["oldest"], Sort::Oldest),
        (&["earliest"], Sort::Oldest),
    ],
    units: &[
        ("b", Measure::Size, 1.0),
        ("bytes", Measure::Size, 1.0),
        ("kb", Measure::Size, 1024.0),
        ("mb", Measure::Size, 1_048_576.0),
        ("megabytes", Measure::Size, 1_048_576.0),
        ("gb", Measure::Size, 1_073_741_824.0),
        ("gigabytes", Measure::Size, 1_073_741_824.0),
        ("s", Measure::Length, 1000.0),
        ("sec", Measure::Length, 1000.0),
        ("secs", Measure::Length, 1000.0),
        ("seconds", Measure::Length, 1000.0),
        ("second", Measure::Length, 1000.0),
        ("min", Measure::Length, 60_000.0),
        ("mins", Measure::Length, 60_000.0),
        ("minutes", Measure::Length, 60_000.0),
        ("minute", Measure::Length, 60_000.0),
        ("h", Measure::Length, 3_600_000.0),
        ("hr", Measure::Length, 3_600_000.0),
        ("hrs", Measure::Length, 3_600_000.0),
        ("hours", Measure::Length, 3_600_000.0),
        ("hour", Measure::Length, 3_600_000.0),
        ("pages", Measure::Pages, 1.0),
        ("page", Measure::Pages, 1.0),
        ("km", Measure::Distance, 1000.0),
        ("kilometers", Measure::Distance, 1000.0),
        ("kilometres", Measure::Distance, 1000.0),
        ("miles", Measure::Distance, 1609.344),
        ("mile", Measure::Distance, 1609.344),
        ("mi", Measure::Distance, 1609.344),
        ("m", Measure::Distance, 1.0),
        ("meters", Measure::Distance, 1.0),
        ("metres", Measure::Distance, 1.0),
        ("ft", Measure::Climb, 0.3048),
        ("feet", Measure::Climb, 0.3048),
    ],
    content_cues: &["of", "about", "with", "showing", "containing", "for"],
    negations: &["not", "no", "without", "except", "excluding"],
    added_verbs: &["added", "uploaded", "shared", "made", "created", "saved"],
    added_dates: &["added", "uploaded", "shared", "saved", "created"],
    modified_dates: &["edited", "changed", "modified", "updated"],
    filler: &[
        "show", "me", "find", "search", "get", "give", "all", "my", "any", "some", "please",
        "files", "file", "stuff", "taken", "shot", "i", "that", "were", "was", "which",
    ],
    joiners: &["and", "or", "&"],
    stop: &[
        "the", "a", "an", "of", "in", "on", "at", "to", "for", "and", "or", "with", "from", "by",
        "is", "are", "it", "this", "that", "my", "me", "i", "we", "our", "us", "be",
    ],
    common: &[
        "nice",
        "reading",
        "bath",
        "split",
        "mobile",
        "orange",
        "march",
        "may",
        "turkey",
        "chile",
        "jordan",
        "georgia",
        "victoria",
        "florence",
        "york",
        "paris",
        "sydney",
        "split",
        "male",
        "bar",
        "bend",
        "hope",
        "liberty",
        "unity",
        "union",
        "concord",
        "independence",
        "phoenix",
        "eugene",
        "austin",
        "jackson",
        "lincoln",
        "madison",
        "warren",
        "marion",
        "salem",
        "dover",
        "troy",
        "athens",
        "rome",
        "carmel",
        "aurora",
    ],
    modifiers: &[
        "photo",
        "picture",
        "pic",
        "image",
        "video",
        "recording",
        "document",
        "spreadsheet",
        "presentation",
        "screenshot",
        "selfie",
        "music",
        "audio",
        "code",
    ],
    camera_brands: &[
        "iphone",
        "ipad",
        "pixel",
        "galaxy",
        "canon",
        "nikon",
        "sony",
        "fuji",
        "fujifilm",
        "olympus",
        "panasonic",
        "lumix",
        "leica",
        "ricoh",
        "gopro",
        "dji",
        "pentax",
        "hasselblad",
    ],
};

/// Other names for a country, folded: "usa" for US.
pub fn country_aliases(code: &str) -> &'static [&'static str] {
    match code {
        "US" => &[
            "usa",
            "us",
            "u.s.",
            "united states",
            "america",
            "the states",
        ],
        "GB" => &[
            "uk",
            "u.k.",
            "britain",
            "great britain",
            "england",
            "scotland",
            "wales",
        ],
        "AE" => &["uae", "emirates"],
        "NL" => &["holland", "the netherlands"],
        "CZ" => &["czech republic", "czechia"],
        "KR" => &["korea", "south korea"],
        "RU" => &["russia"],
        "VN" => &["vietnam"],
        "BO" => &["bolivia"],
        "VE" => &["venezuela"],
        "IR" => &["iran"],
        "TZ" => &["tanzania"],
        "CI" => &["ivory coast"],
        "LA" => &["laos"],
        "SY" => &["syria"],
        "TW" => &["taiwan"],
        "MD" => &["moldova"],
        "VA" => &["vatican"],
        _ => &[],
    }
}
