-- This file should undo anything in `up.sql`
DROP TABLE verifycodes;
ALTER TABLE resetcodes DROP COLUMN setat;
