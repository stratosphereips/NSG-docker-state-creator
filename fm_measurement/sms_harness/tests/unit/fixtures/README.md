# unit-test fixtures

All synthetic archives for test_fm_modules.py are built at runtime in
pytest `tmp_path` by the helpers at the top of `tests/unit/test_fm_modules.py`
(`base_archive`, `probe`, `w`, `wj`, `_fm4_env`, `_fm6_env`, `_run_dir`).
No static fixture files are needed; every docker/tcpdump side effect is
injected via the `config` callables documented in each sms.fm*_*.py docstring.
