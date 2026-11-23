// multilingual-e5-small in JavaScript, as raft5fs-indexer's `embed` runs it
// natively, so both give the same vector for the same text:
//
// - the token ids as the Rust tokenizer gives them, cut to MAX_TOKENS
//   (the first tokens, between <s> and </s>);
// - one text at a time, with no padding;
// - the mean of the last hidden states, made unit length.
//
// ONNX Runtime is passed in, set up by the caller: the embed Worker serves
// its files from the app; the parity test (tests/parity.test.js) runs it in
// Node.
import { Tokenizer } from "@huggingface/tokenizers";

const MAX_TOKENS = 512;

/// The model, ready to embed: `onnx` is the model's bytes, the tokenizer's
/// are parsed JSON.
export async function loadE5(ort, onnx, tokenizerJson, tokenizerConfig) {
  const session = await ort.InferenceSession.create(onnx, { executionProviders: ["wasm"] });
  const tokenizer = new Tokenizer(tokenizerJson, tokenizerConfig);
  const tokenTypes = session.inputNames.includes("token_type_ids");

  function ids(text) {
    const all = tokenizer.encode(text).ids;
    if (all.length <= MAX_TOKENS) return all;
    return [...all.slice(0, MAX_TOKENS - 1), all[all.length - 1]];
  }

  /// The vector of `text`, which already has its "passage: " or "query: ".
  async function embed(text) {
    const tokens = ids(text);
    const n = tokens.length;
    const shape = [1, n];
    const feeds = {
      input_ids: new ort.Tensor("int64", BigInt64Array.from(tokens, BigInt), shape),
      attention_mask: new ort.Tensor("int64", new BigInt64Array(n).fill(1n), shape),
    };
    if (tokenTypes) feeds.token_type_ids = new ort.Tensor("int64", new BigInt64Array(n), shape);
    const out = await session.run(feeds);
    const hidden = out[session.outputNames[0]];
    const dims = hidden.dims[hidden.dims.length - 1];
    const data = hidden.data;
    const v = new Float32Array(dims);
    for (let t = 0; t < n; t++) {
      for (let d = 0; d < dims; d++) v[d] += data[t * dims + d];
    }
    let len = 0;
    for (let d = 0; d < dims; d++) {
      v[d] /= n;
      len += v[d] * v[d];
    }
    len = Math.sqrt(len);
    if (len > 0) for (let d = 0; d < dims; d++) v[d] /= len;
    return v;
  }

  return { embed, ids };
}
