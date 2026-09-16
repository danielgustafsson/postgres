# Copyright (c) 2026, PostgreSQL Global Development Group

waldemort_sources = files('waldemort.c')
waldemort_sources += xlogreader_sources

if host_system == 'windows'
  waldemort_sources += rc_bin_gen.process(win32ver_rc, extra_args: [
    '--NAME', 'waldemort',
    '--FILEDESC', 'WALdemort - generate and corrupt WAL for testing',
  ])
endif

waldemort = executable('waldemort',
  waldemort_sources,
  dependencies: [frontend_code, lz4, zstd],
  c_args: ['-DFRONTEND'],
  kwargs: default_bin_args + {
    'install': false,
  },
)

tests += {
  'name': 'waldemort',
  'sd': meson.current_source_dir(),
  'bd': meson.current_build_dir(),
  'tap': {
    'tests': [
      't/001_waldemort.pl',
      't/002_archive_recovery.pl',
    ],
    'deps': [waldemort],
  },
}
