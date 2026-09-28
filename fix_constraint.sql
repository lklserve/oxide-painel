-- Drop the existing check constraint
ALTER TABLE licenses DROP CONSTRAINT IF EXISTS licenses_duration_type_check;

-- Add the updated check constraint including 'custom'
ALTER TABLE licenses ADD CONSTRAINT licenses_duration_type_check 
CHECK (duration_type IN ('daily', 'weekly', 'monthly', 'permanent', 'custom'));
