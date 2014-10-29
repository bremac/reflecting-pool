from distutils.core import setup


setup(name='poold',
      version='20141028',
      description='A HTTP request replicator daemon',
      author='Brendan MacDonell',
      author_email='brendan@macdonell.net',
      url='https://github.com/bremac/reflecting-pool',
      packages=['poold'],
      package_dir={'poold': 'poold'},
      scripts=['bin/poold_simple'],
      install_requires=['tornado>=4.0.0'],
      requires=['tornado (>=4.0.0)'],
      provides=['poold'])
