// The text side of CLIP for photos (multilingual), in JavaScript, as
// raft5fs-indexer's `clip` runs it natively, so both give a query the same
// vector:
//
// - the token ids as the Rust tokenizer gives them, cut to MAX_TOKENS
//   (the first tokens, between [CLS] and [SEP]);
// - the mean of the last hidden states, through the `Dense` layer (768 to
//   512, no bias), made unit length.
//
// ONNX Runtime is passed in, as for e5.js.
import { Tokenizer } from "@huggingface/tokenizers";

const MAX_TOKENS = 128;
const HIDDEN = 768;
const DIMS = 512;

/// The weights of a safetensors file holding one F32 tensor of `len`.
function readDense(bytes, len) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const head = Number(view.getBigUint64(0, true));
  const data = bytes.subarray(8 + head);
  if (data.byteLength !== len * 4) throw new Error("the photo model's last layer isn't as expected");
  // A copy, aligned for a Float32Array.
  return new Float32Array(data.slice().buffer);
}

/// The model, ready to embed queries: `onnx` and `dense` are bytes, the
/// tokenizer's files parsed JSON.
export async function loadClip(ort, onnx, tokenizerJson, tokenizerConfig, dense) {
  const session = await ort.InferenceSession.create(onnx, { executionProviders: ["wasm"] });
  const tokenizer = new Tokenizer(tokenizerJson, tokenizerConfig);
  const weights = readDense(dense, DIMS * HIDDEN);

  function ids(text) {
    const all = tokenizer.encode(text).ids;
    if (all.length <= MAX_TOKENS) return all;
    return [...all.slice(0, MAX_TOKENS - 1), all[all.length - 1]];
  }

  async function embed(text) {
    const tokens = ids(text);
    const n = tokens.length;
    const shape = [1, n];
    const out = await session.run({
      input_ids: new ort.Tensor("int64", BigInt64Array.from(tokens, BigInt), shape),
      attention_mask: new ort.Tensor("int64", new BigInt64Array(n).fill(1n), shape),
    });
    const hidden = out[session.outputNames[0]].data;
    const mean = new Float32Array(HIDDEN);
    for (let t = 0; t < n; t++) {
      for (let d = 0; d < HIDDEN; d++) mean[d] += hidden[t * HIDDEN + d] / n;
    }
    const v = new Float32Array(DIMS);
    let len = 0;
    for (let j = 0; j < DIMS; j++) {
      let sum = 0;
      for (let i = 0; i < HIDDEN; i++) sum += weights[j * HIDDEN + i] * mean[i];
      v[j] = sum;
      len += sum * sum;
    }
    len = Math.sqrt(len);
    if (len > 0) for (let j = 0; j < DIMS; j++) v[j] /= len;
    return v;
  }

  return { embed, ids };
}
