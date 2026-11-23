//! Prints an ONNX model's inputs and outputs: `cargo run -p raft5fs-indexer --example onnx_io -- <model.onnx>`.
fn main() {
    let path = std::env::args().nth(1).expect("a model");
    let env = ort::init().build().unwrap();
    let session = ort::session::Session::builder(&env)
        .unwrap()
        .commit_from_file(path)
        .unwrap();
    for i in session.inputs() {
        println!("in  {} {:?}", i.name(), i.dtype());
    }
    for o in session.outputs() {
        println!("out {} {:?}", o.name(), o.dtype());
    }
}
