project('ezwebsocket', 'c',
    version : '3.0.2',
    meson_version: '>= 0.50.0',
    license : 'MIT',
    default_options : [ 'c_std=gnu99' ])

cc = meson.get_compiler('c')

pkg = import('pkgconfig')
config_h = configuration_data()

dep_threads = dependency('threads')

if get_option('openssl').enabled()
  dep_ssl = dependency('openssl', version: '>=1.1.0', required: true)
  config_h.set('HAVE_OPENSSL', '1')
else
  dep_ssl = []
endif

inc_public = include_directories('include')
inc_common = [ include_directories('.'), inc_public ]

subdir('include')
subdir('lib')

if get_option('examples').enabled()
  subdir('examples')
endif

configure_file(output: 'config.h', configuration: config_h)
