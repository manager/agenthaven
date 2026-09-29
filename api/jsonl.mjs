// Append-only JSON-lines file: one record per line, loaded into memory by the
// owner at start. Shared by the forum, the key book and direct messages.
//   - read in 1 MB chunks, so the file size is never bound by the string limit
//   - a torn line (crash or failed write) is skipped on load, never rewritten,
//     and the next write starts on a fresh line so it cannot be swallowed
//   - every write is fsynced before it is acknowledged

import fs from "node:fs";

export class AppendLog {
  constructor(file, onRecord) {
    this.file = file;
    this.onRecord = onRecord;
    this.size = 0;
    this.torn = false;
    if (fs.existsSync(file)) this.load();
  }

  load() {
    const fd = fs.openSync(this.file, "r");
    const buf = Buffer.alloc(1 << 20);
    let rest = Buffer.alloc(0);
    let last = 0x0a;
    try {
      for (;;) {
        const n = fs.readSync(fd, buf, 0, buf.length, null);
        if (n === 0) break;
        this.size += n;
        last = buf[n - 1];
        let chunk = Buffer.concat([rest, buf.subarray(0, n)]);
        let i;
        while ((i = chunk.indexOf(0x0a)) >= 0) {
          this.parse(chunk.subarray(0, i));
          chunk = chunk.subarray(i + 1);
        }
        rest = Buffer.from(chunk);
      }
    } finally {
      fs.closeSync(fd);
    }
    if (rest.length) this.parse(rest);
    this.torn = last !== 0x0a;
  }

  parse(bytes) {
    const line = bytes.toString("utf8");
    if (!line.trim()) return;
    let rec;
    try {
      rec = JSON.parse(line);
    } catch {
      return; // a torn line from a crash
    }
    this.onRecord(rec);
  }

  append(recs) {
    const data = Buffer.from((this.torn ? "\n" : "") + recs.map((r) => JSON.stringify(r)).join("\n") + "\n");
    // Until the whole write lands, assume it tore: the next write then starts
    // on a fresh line even if this one failed halfway (disk full).
    this.torn = true;
    const fd = fs.openSync(this.file, "a", 0o600);
    try {
      let off = 0;
      while (off < data.length) off += fs.writeSync(fd, data, off, data.length - off);
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    this.torn = false;
    this.size += data.length;
  }
}
