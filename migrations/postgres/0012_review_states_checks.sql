-- 0010 left three values the review queue writes out of review_states'
-- CHECKs: the needs_attention marker every approve or reject writes first
-- (docs/review-queue.md), and the campaign_merge and
-- false_positive_feedback kinds. Each such write failed the CHECK. The
-- lists below are ReviewKind::ALL and ReviewStatus::ALL in
-- crates/core/src/review.rs; a test in crates/pg/tests keeps them in step.
ALTER TABLE review_states DROP CONSTRAINT IF EXISTS review_states_kind_check;
ALTER TABLE review_states ADD CONSTRAINT review_states_kind_check
    CHECK (kind IN ('cve_link', 'predisclosure_candidate', 'technique_link', 'ioc_publication',
                    'campaign_label', 'campaign_merge', 'false_positive_feedback',
                    'actor_association', 'write_up'));

ALTER TABLE review_states DROP CONSTRAINT IF EXISTS review_states_status_check;
ALTER TABLE review_states ADD CONSTRAINT review_states_status_check
    CHECK (status IN ('open', 'claimed', 'snoozed', 'approved', 'rejected', 'needs_attention'));
