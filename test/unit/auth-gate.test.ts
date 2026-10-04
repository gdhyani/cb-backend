import { Duplex } from "node:stream";
import { BSON, type Document } from "bson";
import { describe, expect, it } from "vitest";
import { runAuthGate } from "../../src/gateway/mongodb/auth-gate.js";

const material = {
  username: "cbu_abcdefgh",
  password: "p".repeat(32),
  salt: Buffer.alloc(16, 7),
  iterations: 4096,
};

/** A fake socket: `feed` delivers bytes from the app, `written` collects what the gate sends back. */
function fakeSocket() {
  const written: Buffer[] = [];
  const socket = new Duplex({
    read() {},
    write(chunk, _enc, cb) {
      written.push(Buffer.from(chunk));
      cb();
    },
  });
  return { socket, written, feed: (b: Buffer) => socket.push(b) };
}

let nextId = 1;
function opMsg(doc: Document, firstKind = 0): Buffer {
  const body = BSON.serialize(doc);
  const header = Buffer.alloc(21);
  header.writeInt32LE(21 + body.length, 0);
  header.writeInt32LE(nextId++, 4);
  header.writeInt32LE(0, 8);
  header.writeInt32LE(2013, 12);
  header.writeUInt32LE(0, 16);
  header.writeUInt8(firstKind, 20);
  return Buffer.concat([header, body]);
}
function opQuery(ns: string, query: Document): Buffer {
  const name = Buffer.from(`${ns}\0`);
  const q = BSON.serialize(query);
  const out = Buffer.concat([Buffer.alloc(16), Buffer.alloc(4), name, Buffer.alloc(8), q]);
  out.writeInt32LE(out.length, 0);
  out.writeInt32LE(nextId++, 4);
  out.writeInt32LE(2004, 12);
  return out;
}
const replies = (bufs: Buffer[]) =>
  bufs.map((b) => BSON.deserialize(b.subarray(21), { promoteValues: true }) as Document);
const sentDocs = (bufs: Buffer[]) => replies(bufs);
const tick = () => new Promise((r) => setImmediate(r));

function setup() {
  const app = fakeSocket();
  const upstream = fakeSocket();
  const gate = runAuthGate(app.socket, upstream.socket, material);
  gate.catch(() => undefined);
  return { app, upstream, gate };
}

describe("mongodb auth gate (S7, FR-GW-002): untrusted input before authentication", () => {
  it("S7 a frame whose declared length is below the header size closes only this client, no throw", async () => {
    const { app, upstream, gate } = setup();
    expect(() => app.feed(Buffer.alloc(16))).not.toThrow();
    await expect(gate).rejects.toThrow();
    expect(app.socket.destroyed).toBe(true);
    expect(upstream.written).toEqual([]);
  });

  it("S7 an oversized declared length is refused before buffering", async () => {
    const { app, gate } = setup();
    const head = Buffer.alloc(16);
    head.writeInt32LE(0x7fffffff, 0);
    head.writeInt32LE(2013, 12);
    expect(() => app.feed(head)).not.toThrow();
    await expect(gate).rejects.toThrow();
    expect(app.socket.destroyed).toBe(true);
  });

  it("S7 an OP_MSG without a kind-0 first section closes the client, no throw", async () => {
    const { app, gate } = setup();
    expect(() => app.feed(opMsg({ hello: 1 }, 1))).not.toThrow();
    await expect(gate).rejects.toThrow();
    expect(app.socket.destroyed).toBe(true);
  });

  it("S7 malformed BSON closes the client, no throw", async () => {
    const { app, gate } = setup();
    const bad = opMsg({ hello: 1 });
    bad.writeInt32LE(9999, 21); // BSON length lies
    expect(() => app.feed(bad)).not.toThrow();
    await expect(gate).rejects.toThrow();
    expect(app.socket.destroyed).toBe(true);
  });

  it("S7 a legacy OP_QUERY 'hello' on a data namespace is never forwarded (no find on the real connection)", async () => {
    const { app, upstream } = setup();
    app.feed(opQuery("shop.users", { hello: { $exists: false } }));
    await tick();
    expect(upstream.written).toEqual([]);
    expect(app.socket.destroyed || app.socket.writableEnded).toBe(true);
  });

  it("FR-GW-002 a legacy OP_QUERY hello on admin.$cmd is forwarded, stripped", async () => {
    const { app, upstream } = setup();
    app.feed(
      opQuery("admin.$cmd", {
        isMaster: 1,
        speculativeAuthenticate: { saslStart: 1 },
        compression: ["zlib"],
      }),
    );
    await tick();
    expect(upstream.written).toHaveLength(1);
    const sent = upstream.written[0] as Buffer;
    expect(sent.includes(Buffer.from("speculativeAuthenticate"))).toBe(false);
    expect(sent.includes(Buffer.from("compression"))).toBe(false);
  });

  it("FR-GW-002 hello reaches the upstream without speculativeAuthenticate, saslSupportedMechs, compression or client metadata", async () => {
    const { app, upstream } = setup();
    app.feed(
      opMsg({
        hello: 1,
        // The gateway already sent the connection's first hello (primary discovery); metadata is only allowed there.
        client: { driver: { name: "nodejs", version: "7" } },
        speculativeAuthenticate: { saslStart: 1, mechanism: "SCRAM-SHA-256" },
        saslSupportedMechs: "admin.cbu_abcdefgh",
        compression: ["zlib"],
        $db: "admin",
      }),
    );
    await tick();
    expect(sentDocs(upstream.written)).toEqual([{ hello: 1, $db: "admin" }]);
  });

  it("S7 any other command before authentication gets Unauthorized (13) and never reaches the upstream", async () => {
    const { app, upstream } = setup();
    app.feed(opMsg({ find: "users", $db: "shop" }));
    await tick();
    expect(upstream.written).toEqual([]);
    expect(replies(app.written)).toEqual([expect.objectContaining({ ok: 0, code: 13 })]);
  });

  it("S7 saslStart with another mechanism is refused with AuthenticationFailed (18)", async () => {
    const { app, gate } = setup();
    app.feed(
      opMsg({ saslStart: 1, mechanism: "SCRAM-SHA-1", payload: new BSON.Binary(Buffer.from("n,,n=x,r=y")) }),
    );
    await expect(gate).rejects.toThrow();
    expect(replies(app.written)).toEqual([expect.objectContaining({ ok: 0, code: 18 })]);
  });

  it("FR-GW-002 frames split across chunks are reassembled", async () => {
    const { app, upstream } = setup();
    const frame = opMsg({ hello: 1, $db: "admin" });
    app.feed(frame.subarray(0, 7));
    app.feed(frame.subarray(7));
    await tick();
    expect(sentDocs(upstream.written)).toEqual([{ hello: 1, $db: "admin" }]);
  });
});
