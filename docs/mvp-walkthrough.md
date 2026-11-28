# MVP walkthrough

The smallest useful loop (#22): an attacker hits a known-weak service, we keep the evidence, we reset the guest, and we export the source addresses. This page has two tracks.

- **Lab track (runnable today).** One Linux machine with Docker. Uses the Docker lab runtime, a local registry and the in-memory mock control plane, all on loopback. Every step is in [`scripts/mvp-lab.sh`](../scripts/mvp-lab.sh), and CI runs that script on every pull request (`MVP lab walkthrough (Docker)`), so this track is known to work.
- **VPS track (production shape).** Ubuntu LTS with KVM, the Workers control plane, Firecracker and the ADR 0003 network. The control plane, agent, gate, protocol, capture and export are the same code as the lab track. The Firecracker driver behind the agent's runtime interface is not written yet (follow-up under #3), so this track cannot be completed end to end today. It is documented so the remaining gap is explicit.

**The Docker lab runtime is not production-safe.** A container is a weaker boundary than a micro-VM (ADR 0002), the agent refuses Docker on a host marked `publicly_exposed`, and the lab binds every port to `127.0.0.1`. Do not put the lab on a public IP.

Before exposing anything on a public IP, read [SECURITY.md](../SECURITY.md), the [threat model](threat-model.md) and [privacy and retention](privacy-and-retention.md), and run the operator checklist in [ADR 0003](adr/0003-network-isolation.md).

## Lab track

Needs: Linux, Docker with Buildx, `sudo` for two firewall rules (`iptables` and `ip6tables`), a Rust toolchain, `curl` and `python3`. Run it all with:

```sh
scripts/mvp-lab.sh
```

What it does, step by step:

1. **Build the demo image** from [`build/recipes/foiled-demo-app`](../build/recipes/foiled-demo-app/README.md) (reproducible, offline build, ADR 0004), load it, and push it to a registry on `127.0.0.1:5000`. The registry gives the image a digest.
2. **Pin the catalogue entry** `foiled/demo-app/1.0.0` to that digest by adding `image: localhost:5000/foiled-demo-app@sha256:...` under `artefact`. The entry already carries its matcher (`foiled-demo-0001-upload-traversal`) and hook. `foiled-lint` checks it. (The script edits the working tree only and restores it at exit.)
3. **Create the lab network** `foiled-lab` with an IPv4 and an IPv6 subnet:

   ```sh
   docker network create --ipv6 --subnet 10.86.0.0/24 --subnet fd00:86::/64 foiled-lab
   ```

   The script adds the firewall rules only after step 6, to show that the agent refuses to start a decoy without them.
4. **Start the mock control plane** in lab mode: `cargo run -p foiled-mock-api -- 127.0.0.1:8787 --lab-host lab-host-1`. It prints an operator token and the job signing public key. Lab mode stands in for Cloudflare's mTLS check for the one lab host, which is acceptable only because it listens on loopback.
5. **Start the host agent** with a `hostd.toml` like this (the script writes it):

   ```toml
   host_id = "lab-host-1"
   api_base = "http://127.0.0.1:8787"   # plain HTTP is only allowed to loopback on a non-public host
   publicly_exposed = false
   sandbox_runtime = "docker"
   allowlist = ["sha256:<digest from step 1>"]
   state_dir = "/tmp/foiled-lab/state"

   [docker]
   network = "foiled-lab"
   subnets = ["10.86.0.0/24", "fd00:86::/64"]   # the network must have exactly these
   bind = "127.0.0.1"
   writable = ["/tmp", "/srv/demo-app"]
   firewall = "iptables"                        # or "nftables"
   firewall_command = ["sudo", "-n"]            # listing rules needs CAP_NET_ADMIN

   [[trusted_keys]]
   id = "lab"
   public_key = "<printed by the mock>"
   ```

6. **No rule, no decoy.** Before every create, and once at start, the agent checks the lab network read only (it never edits firewall rules, #93):

   - `docker` talks to the host's own system daemon: `DOCKER_HOST` is unset or `unix:///var/run/docker.sock` (or `unix:///run/docker.sock`), and `docker context inspect` shows the same socket for the active context. The firewall the agent lists must be the one the decoys' traffic crosses, so a remote (`tcp://`, `ssh://`), rootless or Docker Desktop daemon is refused.
   - `docker network inspect foiled-lab`: the network exists, uses the `bridge` driver and has exactly the configured `subnets`. `docker run` then attaches to that network by its ID, so a network recreated under the same name in the meantime is never used unchecked.
   - `iptables -S` for each IPv4 subnet and `ip6tables -S` for each IPv6 subnet (or `nft -j list ruleset` with `firewall = "nftables"`): starting in `FORWARD` and following jumps in order, a `DROP` or `REJECT` covering every new connection from the subnet must come before anything that could let some of it out, such as Docker's own `-i <bridge> -j ACCEPT`, an earlier `ACCEPT` for one port, or a `RETURN`. Rules for replies (`RELATED,ESTABLISHED`), for traffic into the network and for other networks are ignored. A rule the check does not understand never counts as a deny.

   Each of these commands has 10 seconds; one that runs longer is killed and counts as a failure. If any of that fails, the create job fails with `failure_code: egress_unverified` and a `detail` naming the subnet and, when there is one, the rule that lets traffic out. No container is started and the decoy goes to `failed`. Rotate and reset run the same check before they stop the running decoy, so a failed check leaves it running as it was. The exception is a rotate or reset whose reason indicates compromise (`reverse_shell`, `egress_blocked`, `yara_match`, `canary_used`): the old decoy is still stopped, snapshotted and destroyed, and only then does the job fail with `egress_unverified` and the decoy go to `failed`. The script launches one decoy at this point and checks exactly that, including the `job.ack` audit record.

   Then it adds the rules:

   ```sh
   sudo iptables -I DOCKER-USER -s 10.86.0.0/24 -m conntrack --ctstate NEW -j REJECT
   sudo ip6tables -I DOCKER-USER -s fd00:86::/64 -m conntrack --ctstate NEW -j REJECT
   ```

   Use `-I`, not `-A`: on Docker before 28, `DOCKER-USER` ends in `RETURN`, so an appended rule is never reached, and the agent reports it as shadowed. Replies to inbound connections still flow, and new connections the decoy starts towards other networks are refused. These rules filter forwarded traffic only: a connection to one of the host's own addresses, such as the bridge gateway `10.86.0.1`, goes through the host's `INPUT` chain and is allowed or refused by the host's `INPUT` policy, which the preflight does not check. DNS is not checked either: a decoy on a user-defined network resolves names through Docker's embedded DNS server (`127.0.0.11`), which forwards external lookups for it, so the check does not show that every outbound packet is blocked. Whether decoys need DNS restricted as well is a separate decision. To run the agent as a user without root, give it a sudoers entry for exactly `iptables -S` and `ip6tables -S` (or `nft -j list ruleset`) with `NOPASSWD`, and nothing else.

7. **Launch the decoy** as an operator:

   ```sh
   curl -X POST http://127.0.0.1:8787/v0/decoys -H "authorization: Bearer $TOKEN" \
     -H 'content-type: application/json' -d '{"catalogue_id":"foiled/demo-app/1.0.0"}'
   ```

   The API writes a `decoy.create` job. The agent leases it, checks the signature, host, expiry, replay and allow-list, runs the container read-only with all capabilities dropped, and acknowledges. The decoy goes `pending`, `starting`, `healthy`.
8. **Exploit FOILED-DEMO-0001** with a harmless marker:

   ```sh
   curl -X POST 'http://127.0.0.1:8080/api/upload?path=../../../tmp/foiled-lab-marker.txt' --data 'lab marker'
   ```

   The demo app logs the request and fires the `demo-app.upload-path-traversal` hook. The agent turns both lines into capture envelopes, buffers them and sends them to `/v0/ingest/events`.
9. **Verify egress fails**: from inside the decoy, a TCP connection to `192.0.2.1:80` is refused. The script fails if it succeeds.
10. **Check capture arrived**: the IOC export contains the source address with `FOILED-DEMO-0001` in `hook_cves`.
11. **Rotate** with a reason:

    ```sh
    curl -X POST "http://127.0.0.1:8787/v0/decoys/$DECOY:rotate" -H "authorization: Bearer $TOKEN" \
      -H 'content-type: application/json' -d '{"reason":{"code":"operator_manual","text":"reset after test"}}'
    ```

    The agent stops the container (network first), flushes capture, destroys it and starts a fresh one from the same digest. The decoy reaches generation 2. Evidence already captured stays with the control plane, and anything not yet sent stays in the agent's on-disk buffer under `state_dir`, outside the guest.
12. **Export** with bearer auth:

    ```sh
    curl -H "authorization: Bearer $TOKEN" http://127.0.0.1:8787/v0/exports/iocs.csv
    ```

    ```text
    indicator_type,indicator,first_seen,last_seen,event_count,decoy_ids,catalogue_ids,hook_cves,asn,as_org,country
    ipv4,10.86.0.1,2026-10-18T03:12:40Z,2026-10-18T03:12:41Z,3,<decoy id>,foiled/demo-app/1.0.0,FOILED-DEMO-0001,,,
    ```

**About the address in the lab.** Docker's userland proxy forwards loopback connections, so the decoy sees the bridge gateway (`10.86.0.1`) rather than `127.0.0.1`. On a VPS with the ADR 0003 DNAT rules, the decoy and the export see the attacker's real source address, which is the MVP success metric.

## VPS track

Production shape, per [deploy/vps.md](deploy/vps.md) and [deploy/workers.md](deploy/workers.md):

1. Control plane on Workers: D1 and Postgres migrations applied, `JOB_SIGNING_KEY` and R2 secrets set, the console behind Cloudflare Access, the ingest hostname behind mTLS. This repository never deploys; an operator does.
2. A clean Ubuntu LTS VPS with KVM, users and disk laid out as in the deploy guide, the [nftables ruleset](../configs/nftables/honeypot.nft) loaded, and the host agent enrolled with a client certificate.
3. Build the demo image (ADR 0004) and push it to a registry you control; pin the digest in the catalogue entry and the host allow-list.
4. Run `foiled-hostd` with `sandbox_runtime = "firecracker"`. Today it exits with an error at this step (see below).
5. Launch, exploit, verify egress with the ADR 0003 operator checklist, rotate and export exactly as in the lab track, using the console or the API with your token.

**What is missing today:** step 4 stops. The Firecracker driver is follow-up work under #3, and `foiled-hostd` refuses to start with a runtime it does not have rather than fall back to one that runs nothing (#91). Everything around it (signed jobs, the gate, the executor's rotate and destroy sequences, capture envelopes, the buffer, ingest, export, audit) is the code the lab track exercises.

**Dry runs.** To exercise the control loop without Docker, a lab host that is not publicly exposed can set `sandbox_runtime = "fake"`. That is the recording runtime: every call succeeds and nothing runs. The agent reports `fake` in its heartbeats, the registry shows it, and every decoy it builds is marked as a dry run in the API (`dry_run: true`) and the console, so it is never mistaken for a working decoy. The agent refuses `fake` on a publicly exposed host.

## Not needed for the MVP

The MCP server (#24) and the console launch wizard (#14) come next and build on the same API. MISP, TAXII, YARA, canaries and the LLM correlation worker are not part of the MVP exit.

## Transcript

CI keeps a full transcript of `scripts/mvp-lab.sh` in the `MVP lab walkthrough (Docker)` job log of every pull request. A local run of the same control loop with the recording runtime (`sandbox_runtime = "fake"`, no Docker on the machine) looked like this:

```text
created 5dcb9d987a5f47a6975fc9376a8176e5 pending
after agent: healthy host lab-host-1
[('job.ack', 'lab-host-1', 'accepted'), ('decoy.create', 'dev', 'accepted')]
```
