# -*- coding: utf-8 -*-

import os
from setuptools import setup, find_packages

version = "0.1"

install_requires = [
    'setuptools',
    'jwcrypto',
    ]

setup(
    name='cromlech.jwt',
    version=version,
    author='Cromlech Team',
    author_email='',
    url='http://gitweb.dolmen-project.org',
    download_url='http://pypi.python.org/pypi/cromlech.jwt',
    description='JWT support for Cromlech',
    long_description=(open("README.txt").read() + "\n" +
                      open(os.path.join("docs", "HISTORY.txt")).read()),
    license='ZPL',
    classifiers=[
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Zope Public License',
        'Programming Language :: Python',
        ],
    packages=find_packages('src'),
    package_dir={'': 'src'},
    namespace_packages=['cromlech'],
    include_package_data=True,
    zip_safe=False,
    install_requires=install_requires,
    extras_require={
        },
    )