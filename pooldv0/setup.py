from distutils.core import setup


setup(name='poold',
      version='20140726',
      description='A HTTP request replicator daemon',
      author='Brendan MacDonell',
      author_email='brendan@macdonell.net',
      url='https://github.com/bremac/reflecting-pool',
      scripts=['poold'],
      install_requires=['tornado>=4.0.0'],
      requires=['tornado (>=4.0.0)'],
      provides=['poold'])
