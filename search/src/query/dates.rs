//! Dates in plain English: "2019", "march 2022", "last summer",
//! "christmas 2021", "3 years ago", "between 2018 and 2020", "since may".
//!
//! `read` looks at the words from a position and gives the days they name
//! and how many words that took. Words that only might be a date ("may",
//! "march") count only with a year, after a date word ("in", "since"), or
//! at the end of the query: else they stay text.

use crate::filter::{Dates, Day, civil_from_days, days_from_civil};

/// Today, as days since 1970-01-01, in the searcher's time zone.
#[derive(Debug, Clone, Copy)]
pub struct Today(pub i64);

impl Today {
    pub fn of(now_ms: u64, offset_ms: i64) -> Self {
        Self((now_ms as i64 + offset_ms).div_euclid(86_400_000))
    }

    fn ymd(self) -> (i32, u32, u32) {
        civil_from_days(self.0)
    }
}

const MONTHS: [&[&str]; 12] = [
    &["january", "jan"],
    &["february", "feb"],
    &["march", "mar"],
    &["april", "apr"],
    &["may"],
    &["june", "jun"],
    &["july", "jul"],
    &["august", "aug"],
    &["september", "sep", "sept"],
    &["october", "oct"],
    &["november", "nov"],
    &["december", "dec"],
];

/// Month words that are also common words: they need a year, a date word
/// before them, or the end of the query.
const DOUBTFUL_MONTHS: &[&str] = &["may", "march", "mar", "jan", "jun", "aug", "dec", "sep"];

fn month_of(w: &str) -> Option<u32> {
    MONTHS
        .iter()
        .position(|names| names.contains(&w))
        .map(|i| i as u32 + 1)
}

fn year_of(w: &str) -> Option<i32> {
    let w = w.trim_start_matches('\'');
    if w.len() == 4 && w.chars().all(|c| c.is_ascii_digit()) {
        let y: i32 = w.parse().ok()?;
        return (1900..=2099).contains(&y).then_some(y);
    }
    None
}

fn day_of(w: &str) -> Option<u32> {
    let w = w
        .trim_end_matches(',')
        .trim_end_matches("st")
        .trim_end_matches("nd")
        .trim_end_matches("rd")
        .trim_end_matches("th");
    let d: u32 = w.parse().ok()?;
    (1..=31).contains(&d).then_some(d)
}

fn small_number(w: &str) -> Option<i64> {
    let words = [
        ("a", 1),
        ("an", 1),
        ("one", 1),
        ("two", 2),
        ("three", 3),
        ("four", 4),
        ("five", 5),
        ("six", 6),
        ("seven", 7),
        ("eight", 8),
        ("nine", 9),
        ("ten", 10),
        ("couple", 2),
        ("few", 3),
    ];
    if let Some((_, n)) = words.iter().find(|(s, _)| *s == w) {
        return Some(*n);
    }
    w.parse().ok().filter(|n: &i64| (1..=200).contains(n))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Unit {
    Day,
    Week,
    Month,
    Year,
}

fn unit_of(w: &str) -> Option<Unit> {
    Some(match w.trim_end_matches('s') {
        "day" => Unit::Day,
        "week" => Unit::Week,
        "month" => Unit::Month,
        "year" => Unit::Year,
        _ => return None,
    })
}

fn day(d: i64) -> Day {
    let (y, m, dd) = civil_from_days(d);
    Day::ymd(y, m, dd)
}

fn span(from: i64, to: i64) -> Dates {
    Dates {
        from: Some(day(from)),
        to: Some(day(to)),
    }
}

fn one(d: Day) -> Dates {
    Dates {
        from: Some(d),
        to: Some(d),
    }
}

/// Monday of the week that holds day `d`.
fn monday(d: i64) -> i64 {
    // 1970-01-01 was a Thursday.
    d - (d + 3).rem_euclid(7)
}

/// The month `n` months before (year, month).
fn months_back(y: i32, m: u32, n: i64) -> (i32, u32) {
    let total = i64::from(y) * 12 + i64::from(m) - 1 - n;
    (total.div_euclid(12) as i32, total.rem_euclid(12) as u32 + 1)
}

/// A season, northern hemisphere, by meteorological months: winter is
/// December to February and is named by the year its December is in.
fn season(name: &str, year: i32) -> Option<Dates> {
    let (from, to) = match name {
        "spring" => (Day::month(year, 3), Day::month(year, 5)),
        "summer" => (Day::month(year, 6), Day::month(year, 8)),
        "fall" | "autumn" => (Day::month(year, 9), Day::month(year, 11)),
        "winter" => (Day::month(year, 12), Day::month(year + 1, 2)),
        _ => return None,
    };
    Some(Dates {
        from: Some(from),
        to: Some(to),
    })
}

fn is_season(w: &str) -> bool {
    matches!(w, "spring" | "summer" | "fall" | "autumn" | "winter")
}

/// The last season `name` that has begun by `today`.
fn last_begun_season(name: &str, today: Today) -> Option<Dates> {
    let (y, _, _) = today.ymd();
    [y, y - 1]
        .into_iter()
        .filter_map(|y| season(name, y))
        .find(|d| d.from.is_some_and(|f| f.first() <= today.0))
}

/// Easter Sunday of `year` (the anonymous Gregorian algorithm).
fn easter(year: i32) -> (u32, u32) {
    let a = year % 19;
    let b = year / 100;
    let c = year % 100;
    let d = b / 4;
    let e = b % 4;
    let f = (b + 8) / 25;
    let g = (b - f + 1) / 3;
    let h = (19 * a + b - d - g + 15) % 30;
    let i = c / 4;
    let k = c % 4;
    let l = (32 + 2 * e + 2 * i - h - k) % 7;
    let m = (a + 11 * h + 22 * l) / 451;
    let month = (h + l - 7 * m + 114) / 31;
    let day = (h + l - 7 * m + 114) % 31 + 1;
    (month as u32, day as u32)
}

/// The days a holiday covers in `year`, and how many words name it.
fn holiday(words: &[&str], year: i32) -> Option<(Dates, usize)> {
    let at = |m, d| days_from_civil(year, m, d);
    let w0 = *words.first()?;
    let w1 = words.get(1).copied().unwrap_or("");
    let w2 = words.get(2).copied().unwrap_or("");
    Some(match (w0, w1, w2) {
        ("christmas", "eve", _) => (span(at(12, 24), at(12, 24)), 2),
        ("christmas" | "xmas", _, _) => (span(at(12, 24), at(12, 26)), 1),
        ("new", "year's" | "years" | "year", "eve") => (span(at(12, 31), at(12, 31)), 3),
        ("new", "year's" | "years", _) => (span(at(12, 31), at(12, 31) + 1), 2),
        ("halloween", _, _) => (span(at(10, 31), at(10, 31)), 1),
        ("valentine's" | "valentines", "day", _) => (span(at(2, 14), at(2, 14)), 2),
        ("independence", "day", _) => (span(at(7, 4), at(7, 4)), 2),
        ("fourth", "of", "july") => (span(at(7, 4), at(7, 4)), 3),
        ("thanksgiving", _, _) => {
            // The fourth Thursday of November, and the weekend after.
            let first = at(11, 1);
            let thursday = first + (3 - (first + 3).rem_euclid(7)).rem_euclid(7);
            let day = thursday + 21;
            (span(day, day + 3), 1)
        }
        ("easter", _, _) => {
            let (m, d) = easter(year);
            let sunday = at(m, d);
            (span(sunday - 2, sunday + 1), 1)
        }
        _ => return None,
    })
}

fn is_holiday_start(w: &str) -> bool {
    matches!(
        w,
        "christmas"
            | "xmas"
            | "new"
            | "halloween"
            | "valentine's"
            | "valentines"
            | "independence"
            | "fourth"
            | "thanksgiving"
            | "easter"
    )
}

/// Words that put a date after them.
pub const DATE_CUES: &[&str] = &[
    "in", "from", "during", "on", "of", "since", "after", "before", "until", "till", "between",
];

/// One date, with no range words: its days and its length in words.
/// `cued` says a date word comes before it, `last` that nothing but
/// these words follows.
fn single(words: &[&str], today: Today, cued: bool) -> Option<(Dates, usize)> {
    let w0 = *words.first()?;
    if w0 == "the" {
        let (d, n) = single(&words[1..], today, cued)?;
        return Some((d, n + 1));
    }
    let w1 = words.get(1).copied();
    let w2 = words.get(2).copied();
    let (ty, tm, _) = today.ymd();

    // Relative days.
    match w0 {
        "today" => return Some((span(today.0, today.0), 1)),
        "yesterday" => return Some((span(today.0 - 1, today.0 - 1), 1)),
        _ => {}
    }
    // "this week", "last month", "last summer", "last christmas",
    // "last 3 months", "past two weeks".
    if matches!(w0, "this" | "last" | "past" | "previous") {
        let back = i64::from(w0 != "this");
        if let Some(u) = w1
            .and_then(unit_of)
            .filter(|_| !w1.unwrap_or("").ends_with('s'))
        {
            let d = match u {
                Unit::Day => span(today.0 - back, today.0 - back),
                Unit::Week => {
                    let m = monday(today.0) - 7 * back;
                    span(m, m + 6)
                }
                Unit::Month => {
                    let (y, m) = months_back(ty, tm, back);
                    one(Day::month(y, m))
                }
                Unit::Year => one(Day::year(ty - back as i32)),
            };
            return Some((d, 2));
        }
        if w1 == Some("weekend") {
            let sat = monday(today.0) + 5 - 7 * back;
            return Some((span(sat, sat + 1), 2));
        }
        if let Some(s) = w1.filter(|w| is_season(w)) {
            let d = if back == 0 {
                season(s, if s == "winter" && tm <= 2 { ty - 1 } else { ty })?
            } else {
                // The last one that has ended: in November, this year's
                // summer; in July, last year's.
                [ty, ty - 1, ty - 2]
                    .into_iter()
                    .filter_map(|y| season(s, y))
                    .find(|d| d.to.is_some_and(|t| t.after() <= today.0))?
            };
            return Some((d, 2));
        }
        if w1.is_some_and(is_holiday_start) {
            let rest = &words[1..];
            let years: &[i32] = if back == 0 { &[ty] } else { &[ty, ty - 1] };
            for &y in years {
                if let Some((d, n)) = holiday(rest, y)
                    && (back == 0 || d.to.is_some_and(|t| t.after() <= today.0))
                {
                    return Some((d, n + 1));
                }
            }
        }
        // "last 3 months": up to today.
        if matches!(w0, "last" | "past")
            && let Some(n) = w1.and_then(small_number)
            && let Some(u) = w2.and_then(unit_of)
        {
            let from = match u {
                Unit::Day => today.0 - n + 1,
                Unit::Week => today.0 - 7 * n + 1,
                Unit::Month => {
                    let (y, m) = months_back(ty, tm, n);
                    days_from_civil(y, m, civil_from_days(today.0).2.min(28)) + 1
                }
                Unit::Year => {
                    days_from_civil(ty - n as i32, tm, civil_from_days(today.0).2.min(28)) + 1
                }
            };
            return Some((span(from, today.0), 3));
        }
        // "past few weeks" with no number: as "last 3".
        if w0 == "past"
            && let Some(u) = w1.and_then(unit_of)
        {
            let from = match u {
                Unit::Day => today.0 - 3,
                Unit::Week => today.0 - 21,
                Unit::Month => today.0 - 90,
                Unit::Year => today.0 - 3 * 365,
            };
            return Some((span(from, today.0), 2));
        }
    }
    // "3 years ago", "a month ago".
    if let Some(n) = small_number(w0)
        && let Some(u) = w1.and_then(unit_of)
        && w2 == Some("ago")
    {
        let d = match u {
            Unit::Day => span(today.0 - n, today.0 - n),
            Unit::Week => {
                let m = monday(today.0) - 7 * n;
                span(m, m + 6)
            }
            Unit::Month => {
                let (y, m) = months_back(ty, tm, n);
                one(Day::month(y, m))
            }
            Unit::Year => one(Day::year(ty - n as i32)),
        };
        return Some((d, 3));
    }
    // Decades: "90s", "1990s", "'90s".
    let decade = w0.trim_start_matches('\'').strip_suffix('s').and_then(|d| {
        let n: i32 = d.parse().ok()?;
        match d.len() {
            2 if n % 10 == 0 => Some(if n >= 30 { 1900 + n } else { 2000 + n }),
            4 if n % 10 == 0 && (1900..=2090).contains(&n) => Some(n),
            _ => None,
        }
    });
    if let Some(start) = decade {
        return Some((
            Dates {
                from: Some(Day::year(start)),
                to: Some(Day::year(start + 9)),
            },
            1,
        ));
    }
    // Seasons: "summer 2019", "summer of 2019"; alone, the last begun.
    if is_season(w0) {
        if let Some(y) = w1.and_then(year_of) {
            return Some((season(w0, y)?, 2));
        }
        if w1 == Some("of")
            && let Some(y) = w2.and_then(year_of)
        {
            return Some((season(w0, y)?, 3));
        }
        if cued {
            return Some((last_begun_season(w0, today)?, 1));
        }
        return None;
    }
    // Holidays: with a year; alone after a date word, the last one.
    if is_holiday_start(w0) {
        for y in [ty, ty - 1] {
            if let Some((d, n)) = holiday(words, y) {
                if let Some(year) = words.get(n).and_then(|w| year_of(w)) {
                    return Some((holiday(words, year)?.0, n + 1));
                }
                if cued && d.from.is_some_and(|f| f.first() <= today.0) {
                    return Some((d, n));
                }
            }
        }
        return None;
    }
    // ISO and numeric dates: 2024-06-12, 2024-06, 6/12/2024, 6/2024.
    if let Some(d) = numeric(w0) {
        return Some((one(d), 1));
    }
    // A year.
    if let Some(y) = year_of(w0) {
        return Some((one(Day::year(y)), 1));
    }
    // Month names: "march 5 2024", "march 5", "march 2024", "march";
    // "5 march 2024".
    if let Some(m) = month_of(w0) {
        let mut n = 1;
        let mut d = None;
        if let Some(dd) = w1.and_then(day_of) {
            d = Some(dd);
            n = 2;
        }
        let year = words.get(n).and_then(|w| year_of(w.trim_end_matches(',')));
        if year.is_some() {
            n += 1;
        }
        let doubtful = DOUBTFUL_MONTHS.contains(&w0) && d.is_none() && year.is_none();
        if doubtful && !cued && words.len() > n {
            return None;
        }
        let y = year.unwrap_or_else(|| {
            // The last such month that has begun.
            if m <= tm { ty } else { ty - 1 }
        });
        let day = match d {
            Some(d) => Day::ymd(y, m, d),
            None => Day::month(y, m),
        };
        return Some((one(day), n));
    }
    if let Some(dd) = day_of(w0)
        && let Some(m) = w1.and_then(month_of)
    {
        let year = w2.and_then(year_of);
        let y = year.unwrap_or(if m <= tm { ty } else { ty - 1 });
        return Some((one(Day::ymd(y, m, dd)), 2 + usize::from(year.is_some())));
    }
    None
}

fn numeric(w: &str) -> Option<Day> {
    let parts: Vec<&str> = w.split(['-', '/']).collect();
    let num = |s: &str| s.parse::<i64>().ok();
    match parts.as_slice() {
        [y, m, d] if y.len() == 4 => {
            let (y, m, d) = (num(y)? as i32, num(m)? as u32, num(d)? as u32);
            ((1..=12).contains(&m) && (1..=31).contains(&d)).then(|| Day::ymd(y, m, d))
        }
        [y, m] if y.len() == 4 && m.len() <= 2 && w.contains('-') => {
            let (y, m) = (num(y)? as i32, num(m)? as u32);
            (1..=12).contains(&m).then(|| Day::month(y, m))
        }
        [m, d, y] if y.len() == 4 => {
            let (y, m, d) = (num(y)? as i32, num(m)? as u32, num(d)? as u32);
            ((1..=12).contains(&m) && (1..=31).contains(&d)).then(|| Day::ymd(y, m, d))
        }
        [m, y] if y.len() == 4 && w.contains('/') => {
            let (y, m) = (num(y)? as i32, num(m)? as u32);
            (1..=12).contains(&m).then(|| Day::month(y, m))
        }
        _ => None,
    }
}

/// The day after the last day `d` covers, at the same grain.
fn next(d: Day) -> Day {
    match (d.month, d.day) {
        (None, _) => Day::year(d.year + 1),
        (Some(12), None) => Day::month(d.year + 1, 1),
        (Some(m), None) => Day::month(d.year, m + 1),
        _ => day(d.after()),
    }
}

/// The day before the first day `d` covers, at the same grain.
fn previous(d: Day) -> Day {
    match (d.month, d.day) {
        (None, _) => Day::year(d.year - 1),
        (Some(1), None) => Day::month(d.year - 1, 12),
        (Some(m), None) => Day::month(d.year, m - 1),
        _ => day(d.first() - 1),
    }
}

/// The dates the words at the start of `words` name, with any date word
/// before them, and how many words that took. `None` if they name none.
pub fn read(words: &[&str], today: Today) -> Option<(Dates, usize)> {
    let w0 = *words.first()?;
    let rest = &words[1..];
    match w0 {
        "between" => {
            let (a, n) = single(rest, today, true)?;
            if rest.get(n) != Some(&"and") {
                return None;
            }
            let (b, m) = single(&rest[n + 1..], today, true)?;
            return Some((
                Dates {
                    from: a.from,
                    to: b.to,
                },
                1 + n + 1 + m,
            ));
        }
        "since" => {
            let (a, n) = single(rest, today, true)?;
            return Some((
                Dates {
                    from: a.from,
                    to: None,
                },
                1 + n,
            ));
        }
        "after" => {
            let (a, n) = single(rest, today, true)?;
            return Some((
                Dates {
                    from: a.to.map(next),
                    to: None,
                },
                1 + n,
            ));
        }
        "before" => {
            let (a, n) = single(rest, today, true)?;
            return Some((
                Dates {
                    from: None,
                    to: a.from.map(previous),
                },
                1 + n,
            ));
        }
        "until" | "till" => {
            let (a, n) = single(rest, today, true)?;
            return Some((
                Dates {
                    from: None,
                    to: a.to,
                },
                1 + n,
            ));
        }
        "in" | "from" | "during" | "on" | "of" => {
            let (a, n) = single(rest, today, true)?;
            return Some(
                range_after(a, &rest[n..], today).map_or((a, 1 + n), |(d, m)| (d, 1 + n + m)),
            );
        }
        _ => {}
    }
    // A year range written as one word: 2018-2020.
    if let Some((a, b)) = w0.split_once(['-', '–'])
        && let (Some(a), Some(b)) = (year_of(a), year_of(b))
        && a <= b
    {
        return Some((
            Dates {
                from: Some(Day::year(a)),
                to: Some(Day::year(b)),
            },
            1,
        ));
    }
    let (a, n) = single(words, today, false)?;
    Some(range_after(a, &words[n..], today).map_or((a, n), |(d, m)| (d, n + m)))
}

/// "to 2020" or "- 2020" after a date: the range from `a` to that date.
fn range_after(a: Dates, words: &[&str], today: Today) -> Option<(Dates, usize)> {
    let w0 = *words.first()?;
    if !matches!(w0, "to" | "-" | "–" | "through" | "thru" | "and") {
        return None;
    }
    // "and" joins two dates of one key, which the parser makes two terms.
    if w0 == "and" {
        return None;
    }
    let (b, n) = single(&words[1..], today, true)?;
    Some((
        Dates {
            from: a.from,
            to: b.to,
        },
        1 + n,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Friday 27 November 2026.
    fn today() -> Today {
        Today(days_from_civil(2026, 11, 27))
    }

    fn dates(s: &str) -> Option<(String, usize)> {
        let words: Vec<&str> = s.split_whitespace().collect();
        read(&words, today()).map(|(d, n)| (d.to_string(), n))
    }

    fn whole(s: &str) -> String {
        let n = s.split_whitespace().count();
        match dates(s) {
            Some((d, m)) if m == n => d,
            other => panic!("{s:?} read as {other:?}"),
        }
    }

    #[test]
    fn plain_dates() {
        assert_eq!(whole("2019"), "2019");
        assert_eq!(whole("march 2022"), "2022-03");
        assert_eq!(whole("march 5 2022"), "2022-03-05");
        assert_eq!(whole("march 5th, 2022"), "2022-03-05");
        assert_eq!(whole("5 march 2022"), "2022-03-05");
        assert_eq!(whole("2024-06-12"), "2024-06-12");
        assert_eq!(whole("2024-06"), "2024-06");
        assert_eq!(whole("6/12/2024"), "2024-06-12");
        assert_eq!(whole("6/2024"), "2024-06");
        assert_eq!(whole("the 90s"), "1990..1999");
        assert_eq!(whole("in the summer of 2019"), "2019-06..2019-08");
    }

    #[test]
    fn decades_and_seasons() {
        assert_eq!(whole("90s"), "1990..1999");
        assert_eq!(whole("1980s"), "1980..1989");
        assert_eq!(whole("summer 2019"), "2019-06..2019-08");
        assert_eq!(whole("summer of 2019"), "2019-06..2019-08");
        assert_eq!(whole("winter 2020"), "2020-12..2021-02");
        // In November, the summer just past; "last winter" is the one
        // that ended in February.
        assert_eq!(whole("last summer"), "2026-06..2026-08");
        assert_eq!(whole("last winter"), "2025-12..2026-02");
        let july = Today(days_from_civil(2026, 7, 10));
        let summer = read(&["last", "summer"], july).unwrap().0.to_string();
        assert_eq!(summer, "2025-06..2025-08", "in July, last year's");
        assert_eq!(whole("this summer"), "2026-06..2026-08");
        assert_eq!(whole("in summer"), "2026-06..2026-08");
        assert_eq!(dates("summer"), None, "alone, a season stays text");
    }

    #[test]
    fn relative_dates() {
        assert_eq!(whole("today"), "2026-11-27");
        assert_eq!(whole("yesterday"), "2026-11-26");
        assert_eq!(whole("this week"), "2026-11-23..2026-11-29");
        assert_eq!(whole("last week"), "2026-11-16..2026-11-22");
        assert_eq!(whole("last month"), "2026-10");
        assert_eq!(whole("this year"), "2026");
        assert_eq!(whole("last year"), "2025");
        assert_eq!(whole("last weekend"), "2026-11-21..2026-11-22");
        assert_eq!(whole("3 years ago"), "2023");
        assert_eq!(whole("a month ago"), "2026-10");
        assert_eq!(whole("last 3 months"), "2026-08-28..2026-11-27");
        assert_eq!(whole("past two weeks"), "2026-11-14..2026-11-27");
    }

    #[test]
    fn holidays() {
        assert_eq!(whole("christmas 2021"), "2021-12-24..2021-12-26");
        assert_eq!(whole("christmas eve 2021"), "2021-12-24");
        assert_eq!(whole("thanksgiving 2024"), "2024-11-28..2024-12-01");
        assert_eq!(whole("easter 2024"), "2024-03-29..2024-04-01");
        assert_eq!(whole("last christmas"), "2025-12-24..2025-12-26");
        assert_eq!(whole("from thanksgiving"), "2026-11-26..2026-11-29");
        assert_eq!(dates("christmas"), None, "alone, a holiday stays text");
    }

    #[test]
    fn ranges() {
        assert_eq!(whole("between 2018 and 2020"), "2018..2020");
        assert_eq!(whole("from 2018 to 2020"), "2018..2020");
        assert_eq!(whole("2018-2020"), "2018..2020");
        assert_eq!(whole("since may"), "2026-05..");
        assert_eq!(whole("since 2020"), "2020..");
        assert_eq!(whole("after 2015"), "2016..");
        assert_eq!(whole("after march 2020"), "2020-04..");
        assert_eq!(whole("before 2010"), "..2009");
        assert_eq!(whole("until june 2020"), "..2020-06");
    }

    #[test]
    fn doubtful_months_need_a_reason() {
        // "may" with nothing after it ends the query: a date.
        assert_eq!(whole("may"), "2026-05");
        assert_eq!(whole("in may"), "2026-05");
        assert_eq!(whole("may 2020"), "2020-05");
        // Followed by more words, alone: not a date.
        assert_eq!(dates("may be useful"), None);
        assert_eq!(dates("march madness"), None);
        // A month not yet come this year is last year's.
        assert_eq!(whole("in december"), "2025-12");
        assert_eq!(
            dates("2000 km"),
            Some(("2000".into(), 1)),
            "the parser checks units"
        );
    }
}
