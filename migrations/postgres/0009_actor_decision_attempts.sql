-- The attempts an actor link decision covered when it was made (#29). A
-- confirmation applies to these only: attempts that join a campaign later
-- are not confirmed by it and send the link back to review. Rows written
-- before this column existed cover no attempts, so their confirmations
-- export nothing until an analyst confirms again.
ALTER TABLE actor_link_decisions
    ADD COLUMN IF NOT EXISTS attempt_ids text[] NOT NULL DEFAULT '{}';
