# Attempt timeline

The timeline answers "what did this source do to this decoy?" without anyone logging in to a dead guest (#10). It is the read model of one [attempt](attempts.md) (#25): the attempt's capture events in time order, the points where its state moved, the payloads and IOCs linked to it, and a recipe for cutting the matching pcap slice for Wireshark. Earlier drafts called this "session replay"; [session-replay.md](session-replay.md) now points here.

The timeline is **read-only**. It never changes or deletes capture events, and Foiled never re-sends captured traffic onto any network. Active replay against live systems is out of scope for this project for good.

The contract is [`schemas/attempt-timeline.schema.json`](../schemas/attempt-timeline.schema.json). The code is `foiled_core::timeline`.

## Correlation

Which events belong to an attempt is decided by the attempt grouping in [attempts.md](attempts.md#grouping) (#25), not here. The timeline takes an attempt and the capture events, keeps only the events the attempt lists, and orders them by time and then event id. There is no second set of correlation rules to keep in step.

## API

`GET /v0/attempts/{attempt_id}/timeline` (scope `attempts:read`, [OpenAPI](../api/openapi.yaml)) returns the timeline as JSON. Add `format=text` for the plain-text rendering. Pass the same `since` and `until` as the list call for attempts older than 7 days, as with `GET /v0/attempts/{attempt_id}` (#21).

The operator console (#14) uses this endpoint for the attempt detail view. A `foiled attempts show <id> --format=json|text` command will wrap the same endpoint when the CLI exists; until then use the API.

```sh
curl -sS -H "authorization: Bearer $FOILED_TOKEN" \
  "$FOILED_API/v0/attempts/att_43065706a9ac936e970054e5/timeline?format=text"
```

### JSON

| Field | Meaning |
| --- | --- |
| `attempt_id`, `decoy_id`, `catalogue_id`, `src` | From the attempt. |
| `first_seen`, `last_seen`, `state` | From the attempt. Unix ms. |
| `entries[]` | One per event: `seq` (from 1), `ts`, `t_offset_ms` since the first event, `channel`, `severity`, a one-line `summary`, `state_change` when the attempt moved state at this event, and the unchanged capture envelope as `event`. |
| `payload_refs`, `ioc_refs` | R2 objects and IOCs linked to the attempt (#9, #34). |
| `pcap` | How to cut the pcap slice (below). |
| `notes` | Caveats for the reader, such as TLS without keys. |
| `missing_event_ids` | Events the attempt lists that are no longer stored, for example after the retention purge (#16). |

One entry from the demo exploit, in full in the [golden file](../testdata/attempts/timeline/demo-fleet-2.json):

```json
{
  "seq": 3,
  "ts": 1792285384010,
  "t_offset_ms": 1010,
  "channel": "hook",
  "severity": "high",
  "summary": "hook demo-app.upload-path-traversal fired at trigger (FOILED-DEMO-0001)",
  "state_change": { "state": "exploit", "signal": "hook_trigger" },
  "event": { "event_id": "x3", "channel": "hook", "...": "the capture envelope" }
}
```

### Text

```text
attempt att_43065706a9ac936e970054e5  203.0.113.7 -> dcy-demo-1 (foiled/demo-app/1.0.0)
state post-exploitation  first seen 2026-10-18T01:03:03Z  last seen 2026-10-18T01:03:05Z  5 event(s)
   1  +   0.000s  application info     GET /admin
                   state -> probe (first_contact)
   2  +   1.000s  application info     POST /api/upload?path=../../tmp/x.sh
   3  +   1.010s  hook        high     hook demo-app.upload-path-traversal fired at trigger (FOILED-DEMO-0001)
                   state -> exploit (hook_trigger)
   4  +   1.020s  hook        high     hook demo-app.upload-path-traversal fired at post_exploit (FOILED-DEMO-0001)
                   state -> post-exploitation (hook_post_exploit)
   5  +   2.000s  egress      info     egress to 192.0.2.80:80 (blocked)
pcap filter 'host 203.0.113.7' from 2026-10-18T01:02:58Z to 2026-10-18T01:03:10Z
```

Times are UTC. Through the API the state moves to `exploit` one event earlier, at event 2 with signal `matcher`, because the API passes tier 1 signature hits into the grouping ([exploit-attribution.md](exploit-attribution.md)). The golden file is built without them.

### Attacker text

Paths, commands, headers and file names in summaries are attacker-controlled. Summaries are built only from known envelope fields, control characters (including CR and LF) and bidi overrides are escaped as `\u{..}`, and each summary is capped at 160 characters. A request line cannot forge an extra timeline row or reverse the reading direction of a file name. The full envelope in `event` is unchanged, so consumers that render it must escape it themselves.

## Pcap extract

Each decoy has a tcpdump ring on the host side of its tap: 20 files of 100 MB in `/var/lib/foiled/capture/<decoy-id>/ring.pcapNN`, written by [`foiled-capture@.service`](../deploy/systemd/foiled-capture@.service) ([vps.md](deploy/vps.md#pcap-disk-caps)). `foiled-hostd` uploads closed files to R2 and deletes the local copy (#9), under the [ADR 0005](adr/0005-capture-layer.md#payload_ref-and-the-r2-key-layout) key layout with `_` for the attempt, because one ring file spans many attempts.

The `pcap` block gives everything needed to cut one attempt out of that:

| Field | Example | Meaning |
| --- | --- | --- |
| `filter` | `host 203.0.113.7` | BPF filter. Built only when `src` parses as an IP address; otherwise empty, with a note. |
| `from_ms`, `to_ms` | | The attempt's window padded by 5 seconds on each side. |
| `host_glob` | `dcy-demo-1/ring.pcap*` | Ring files still on the host, relative to `/var/lib/foiled/capture`. |
| `r2_prefix` | `t1/dcy-demo-1/_/network/` | Where uploaded ring files are in the evidence bucket. |
| `output_path` | `attempts/att_.../attempt.pcap` | Where to write the slice, relative to your working directory. |

Steps, with Wireshark's `mergecap` and `editcap` and `tcpdump`:

1. Fetch the timeline JSON and read the `pcap` block.

   ```sh
   curl -sS -H "authorization: Bearer $FOILED_TOKEN" \
     "$FOILED_API/v0/attempts/$ATTEMPT/timeline" > timeline.json
   FILTER=$(jq -r .pcap.filter timeline.json)
   FROM=$(jq -r '.pcap.from_ms / 1000 | floor | strftime("%Y-%m-%d %H:%M:%S")' timeline.json)
   TO=$(jq -r '.pcap.to_ms / 1000 | ceil | strftime("%Y-%m-%d %H:%M:%S")' timeline.json)
   OUT=$(jq -r .pcap.output_path timeline.json)
   ```

2. Get the ring files that cover the window. For recent attempts they may still be on the host under `host_glob`. Otherwise copy the objects under `r2_prefix` from the evidence bucket with an R2 token that can read it; there is no download endpoint in the MVP. Each uploaded file is also referenced by the `payload_ref` of its `network` capture event.
3. Merge them and cut the window. `jq` prints UTC and `editcap` reads these times as local time, so run it in UTC.

   ```sh
   mergecap -w merged.pcap rings/ring.pcap*
   TZ=UTC editcap -A "$FROM" -B "$TO" merged.pcap window.pcap
   ```

4. Keep only the attacker's traffic and open it.

   ```sh
   mkdir -p "$(dirname "$OUT")"
   tcpdump -r window.pcap -w "$OUT" "$FILTER"
   wireshark "$OUT"
   ```

If `filter` is empty, stop at step 3. The attempt's source was not an IP address, so there is nothing safe to filter on, and `tcpdump` with an empty filter would keep every other source's traffic in the window too.

Pcaps are personal information and live malware traffic. Keep slices on the analyst workstation's encrypted disk, delete them when done, and remember that R2 deletes the ring files after the pcap TTL (14 days by default, [privacy-and-retention.md](privacy-and-retention.md)).

## Encrypted traffic

Decoys usually do not hold TLS session keys for attacker connections, so for HTTPS the pcap shows handshakes, timing and sizes, not request bodies. Request details in the timeline then come only from what the decoy itself logged (application events and hooks), which the guest could have tampered with after a compromise. When any of the attempt's events is TLS or on port 443, the timeline adds a note saying so. Do not read a missing body in the pcap as "nothing was sent".

## Related

- [attempts.md](attempts.md): grouping and state (#25).
- [api/control-plane.md](api/control-plane.md): the API and its OpenAPI contract (#21).
- #14 operator console attempt detail view.
- [privacy-and-retention.md](privacy-and-retention.md): why events and pcaps go missing over time (#16).
