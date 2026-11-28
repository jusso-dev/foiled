-- Dry-run decoys and the runtime each agent reports (#91).
--
-- `decoys.dry_run` is set from the host's job result when the host runs the
-- recording runtime (`sandbox_runtime = "fake"`): the decoy may say healthy,
-- but nothing runs and nothing is captured.
ALTER TABLE decoys ADD COLUMN dry_run INTEGER NOT NULL DEFAULT 0;

-- The runtime named in the agent's last heartbeat. NULL until a heartbeat
-- arrives, and for agents that predate the field.
ALTER TABLE agents ADD COLUMN sandbox_runtime TEXT
    CHECK (sandbox_runtime IS NULL OR sandbox_runtime IN ('firecracker', 'docker', 'fake'));
