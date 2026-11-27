//! Prints how each argument reads as filters and text, against the
//! vocabulary of data/parse.json: `cargo run -p raft5fs-eval --example
//! parse_one -- "photos from lisbon"`.

fn main() {
    let set = raft5fs_eval::parse::pinned();
    let v = set.vocabulary();
    for q in std::env::args().skip(1) {
        let p = raft5fs_search::query::parse(&q, &v, set.now_ms(), 0);
        println!("{q:?} -> [{}] {:?}", p.filter, p.text);
    }
}
