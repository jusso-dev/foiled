-- Key capture events on the sending identity as well (#31). With
-- (tenant_id, event_id) alone, one sensor could pre-claim an event id that
-- another sensor of the same tenant would later send, and the real event
-- would be dropped as a duplicate. Ingest stamps source_kind and source_id
-- from the client certificate, so the key cannot be chosen by the sender.
ALTER TABLE capture_events DROP CONSTRAINT IF EXISTS capture_events_pkey;
ALTER TABLE capture_events ADD CONSTRAINT capture_events_pkey
    PRIMARY KEY (tenant_id, source_kind, source_id, event_id);
