// The page's handle on the Worker (see worker.js). Every method returns a
// promise; a failure rejects with an Error whose `code` names the errno.
// `end` terminates the Worker, which drops every key it held.

export function connect({ onStorageError } = {}) {
  let worker = new Worker(new URL("./worker.js", import.meta.url), {
    type: "module",
  });
  let next = 1;
  const calls = new Map();

  worker.onmessage = ({ data }) => {
    if (data.event === "storage-error") {
      onStorageError?.(data.message);
      return;
    }
    const call = calls.get(data.id);
    if (!call) return;
    if (data.progress) {
      call.progress?.(data.progress.done, data.progress.total);
      return;
    }
    calls.delete(data.id);
    if (data.error) {
      call.reject(Object.assign(new Error(data.error.message), { code: data.error.code }));
    } else {
      call.resolve(data.value);
    }
  };
  worker.onerror = (e) => {
    for (const call of calls.values()) call.reject(new Error(e.message || "the worker failed"));
    calls.clear();
  };

  function call(method, args, progress) {
    if (!worker) return Promise.reject(new Error("logged out"));
    const id = next++;
    return new Promise((resolve, reject) => {
      calls.set(id, { resolve, reject, progress });
      worker.postMessage({ id, method, args });
    });
  }

  return {
    enrol: (invitation, password) => call("enrol", [invitation, password]),
    login: (fsId, user, password, stay) => call("login", [fsId, user, password, !!stay]),
    resume: () => call("resume", []),
    visit: (link) => call("visit", [link]),
    checkNewPassword: (password) => call("checkNewPassword", [password]),
    whoami: () => call("whoami", []),
    readdir: (path) => call("readdir", [path]),
    stat: (path) => call("stat", [path]),
    mkdir: (path) => call("mkdir", [path]),
    remove: (path) => call("remove", [path]),
    rename: (from, to) => call("rename", [from, to]),
    copy: (from, to) => call("copy", [from, to]),
    upload: (path, file, overwrite, progress) =>
      call("upload", [path, file, overwrite], progress),
    download: (path, progress, type) => call("download", [path, type], progress),
    preview: (path, kind, width, height) => call("preview", [path, kind, width, height]),
    readText: (path, max) => call("readText", [path, max]),
    openFile: (path) => call("openFile", [path]),
    readFile: (handle, offset, len) => call("readFile", [handle, offset, len]),
    closeFile: (handle) => call("closeFile", [handle]),
    isPinned: (user) => call("isPinned", [user]),
    share: (path, user, writable, label, fingerprint) =>
      call("share", [path, user, writable, label, fingerprint ?? null]),
    sharedWith: (path) => call("sharedWith", [path]),
    revoke: (path, user) => call("revoke", [path, user]),
    pending: () => call("pending", []),
    trust: (user, words) => call("trust", [user, words]),
    forgetKey: (user) => call("forgetKey", [user]),
    account: () => call("account", []),
    issueInvite: (user, caps) => call("issueInvite", [user, caps]),
    listInvites: () => call("listInvites", []),
    cancelInvite: (user) => call("cancelInvite", [user]),
    createLink: (path, label, expires) => call("createLink", [path, label, expires ?? null]),
    listLinks: () => call("listLinks", []),
    revokeLink: (user) => call("revokeLink", [user]),
    pruneStatus: () => call("pruneStatus", []),
    pruneEstimate: (path) => call("pruneEstimate", [path]),
    pruneAgain: (path) => call("pruneAgain", [path]),
    pausePruning: () => call("pausePruning", []),
    resumePruning: () => call("resumePruning", []),
    pruning: () => call("pruning", []),

    /// Stores what is buffered, then ends the Worker.
    async end() {
      try {
        await call("logout", []);
      } finally {
        worker?.terminate();
        worker = null;
      }
    },
    /// Ends the Worker at once, as for an idle lock.
    kill() {
      worker?.terminate();
      worker = null;
    },
  };
}
