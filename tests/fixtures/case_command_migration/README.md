# Legacy command migration fixtures

`legacy_cases.json` retains 23 small command records, without benchmark source
code or model data. They cover all ten distinct Vul4C baseline script bodies in
the local prepared cases and representative Python, JavaScript and Go commands,
including dependency patches, changed working directories, multi-command tests
and independent Unit commands that originally omitted the candidate patch.
Additional cases retain Jest/npm entry points, dependency vendoring, Ansible
entry points, test-file preparation and a malformed shebang joined to a stray
Mocha command that must be removed before candidate installation.

`tests/test_case_command_migration.py` migrates and runs these scripts using real
Bash and the exact-source protocol. Checkout/build/test executables are local
doubles. Success, build/test failures, source mutation, baseline restoration,
preflight rejection, original-record backups and repeat execution are checked.
The tests require no external model packages, Docker daemon, images or network.
