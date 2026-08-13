BEGIN;
ALTER TABLE verdicts
  ADD COLUMN IF NOT EXISTS azure_management_groups TEXT[],
  ADD COLUMN IF NOT EXISTS azure_subscriptions_listed TEXT[],
  ADD COLUMN IF NOT EXISTS azure_subscriptions_scanned TEXT[];
COMMIT;
