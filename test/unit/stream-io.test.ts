import { Readable } from "node:stream";
import { describe, expect, it } from "vitest";
import { readExact, readLine } from "../../src/gateway/stream-io.js";

const source = () => new Readable({ read() {} });

describe("FR-GW-003 stream-io: reading upstream frames", () => {
  it("readExact waits for the rest of a frame that arrives in a later packet (no spin)", async () => {
    const s = source();
    s.push(Buffer.from("hello"));
    setTimeout(() => s.push(Buffer.from("world!")), 20);
    const got = await readExact(s, 10);
    expect(got.toString()).toBe("helloworld");
    // the extra byte stays readable for the next frame
    expect((await readExact(s, 1)).toString()).toBe("!");
  }, 2000);

  it("readExact leaves no listeners behind after many partial reads", async () => {
    const s = source();
    for (let i = 0; i < 30; i++) {
      setTimeout(() => s.push(Buffer.from("x")), i);
    }
    await readExact(s, 30);
    expect(s.listenerCount("readable")).toBe(0);
    expect(s.listenerCount("end")).toBe(0);
    expect(s.listenerCount("error")).toBe(0);
  }, 2000);

  it("readExact fails when the upstream closes mid-frame", async () => {
    const s = source();
    s.push(Buffer.from("abc"));
    setTimeout(() => s.push(null), 10);
    await expect(readExact(s, 10)).rejects.toThrow(/closed/);
  }, 2000);

  it("readLine returns one line and keeps the rest", async () => {
    const s = source();
    s.push(Buffer.from("250 ok\r\nnext"));
    expect(await readLine(s)).toBe("250 ok");
    expect((await readExact(s, 4)).toString()).toBe("next");
  }, 2000);
});
