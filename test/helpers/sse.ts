/** Test stand-in for the agent's event stream: collects parsed SSE events for one device + environment. */
export function openEvents(base: string, token: string, envId: string) {
  const events: { event: string; data: Record<string, unknown> }[] = [];
  const abort = new AbortController();
  let status = 0;
  const done = (async () => {
    const res = await fetch(`${base}/api/agent/events?envId=${envId}`, {
      headers: { authorization: `Bearer ${token}`, accept: "text/event-stream" },
      signal: abort.signal,
    });
    status = res.status;
    if (!res.body) return;
    const decoder = new TextDecoder();
    let buf = "";
    for await (const chunk of res.body) {
      buf += decoder.decode(chunk as Uint8Array, { stream: true });
      let i = buf.indexOf("\n\n");
      while (i >= 0) {
        const block = buf.slice(0, i);
        buf = buf.slice(i + 2);
        const event = /^event: (.+)$/m.exec(block)?.[1];
        const data = /^data: (.+)$/m.exec(block)?.[1];
        if (event) events.push({ event, data: data ? JSON.parse(data) : {} });
        i = buf.indexOf("\n\n");
      }
    }
  })().catch(() => undefined);
  return {
    events,
    status: () => status,
    of: (name: string) => events.filter((e) => e.event === name).map((e) => e.data),
    close: async () => {
      abort.abort();
      await done;
    },
  };
}

export async function waitFor<T>(
  check: () => T | undefined | false | Promise<T | undefined | false>,
  ms = 5000,
  every = 20,
): Promise<T> {
  const until = Date.now() + ms;
  for (;;) {
    const v = await check();
    if (v) return v;
    if (Date.now() > until) throw new Error("waitFor: timed out");
    await new Promise((r) => setTimeout(r, every));
  }
}
