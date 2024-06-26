CREATE EXTENSION injection_points;

SELECT injection_points_attach('TestInjectionBooh', 'booh');
SELECT injection_points_attach('TestInjectionError', 'error');
SELECT injection_points_attach('TestInjectionLog', 'notice');
SELECT injection_points_attach('TestInjectionLog2', 'notice');

SELECT injection_points_run('TestInjectionBooh'); -- nothing
SELECT injection_points_run('TestInjectionLog2'); -- notice
SELECT injection_points_run('TestInjectionLog'); -- notice
SELECT injection_points_run('TestInjectionError'); -- error

-- Re-load cache and run again.
\c
SELECT injection_points_run('TestInjectionLog2'); -- notice
SELECT injection_points_run('TestInjectionLog'); -- notice
SELECT injection_points_run('TestInjectionError'); -- error

-- Remove one entry and check the remaining entries.
SELECT injection_points_detach('TestInjectionError'); -- ok
SELECT injection_points_run('TestInjectionLog'); -- notice
SELECT injection_points_run('TestInjectionError'); -- nothing
-- More entries removed, letting TestInjectionLog2 to check the same
-- callback used in more than one point.
SELECT injection_points_detach('TestInjectionLog'); -- ok
SELECT injection_points_run('TestInjectionLog'); -- nothing
SELECT injection_points_run('TestInjectionError'); -- nothing
SELECT injection_points_run('TestInjectionLog2'); -- notice

SELECT injection_points_detach('TestInjectionLog'); -- fails

SELECT injection_points_run('TestInjectionLog2'); -- notice
SELECT injection_points_detach('TestInjectionLog2');

-- Runtime conditions
SELECT injection_points_attach('TestConditionError', 'error');
-- Any follow-up injection point attached will be local to this process.
SELECT injection_points_set_local();
SELECT injection_points_attach('TestConditionLocal1', 'error');
SELECT injection_points_attach('TestConditionLocal2', 'notice');
SELECT injection_points_run('TestConditionLocal1'); -- error
SELECT injection_points_run('TestConditionLocal2'); -- notice
-- reload, local injection points should be gone.
\c
SELECT injection_points_run('TestConditionLocal1'); -- nothing
SELECT injection_points_run('TestConditionLocal2'); -- nothing
SELECT injection_points_run('TestConditionError'); -- error
SELECT injection_points_detach('TestConditionError');
-- Attaching injection points that use the same name as one defined locally
-- previously should work.
SELECT injection_points_attach('TestConditionLocal1', 'error');
SELECT injection_points_detach('TestConditionLocal1');

DROP EXTENSION injection_points;
