-- Statistics for the expression indexes of 20261010150000_add_lowercase_prefix_indexes.
--
-- Until a table is analyzed the planner knows nothing about lower(name) and, with no
-- estimate to go on, walks an older index in full instead of using the new one: the
-- suggestions stayed as slow as without the indexes (about 2 s on the OSV names) until
-- autovacuum happened to analyze the table, which on tables that rarely change can be
-- never. A few seconds per table.

ANALYZE "NVDAffectedPackage";
ANALYZE "OSVAffectedPackage";
ANALYZE "CnaAffectedProduct";
