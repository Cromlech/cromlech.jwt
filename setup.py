# -*- coding: utf-8 -*-

import os
from setuptools import setup, find_packages

version = "0.2.1"


install_requires = [
    'setuptools',
    'jwcrypto >= 1.4',
    'pytz',
]


test_requires = [
    'pytest',
]


def desc(*paths):
    desc = ""
    for path in paths:
        desc += open(path).read() + "\n"
    return desc


setup(
    name='cromlech.jwt',
    version=version,
    author='Cromlech Team',
    author_email='',
    url='http://gitweb.dolmen-project.org',
    download_url='http://pypi.python.org/pypi/cromlech.jwt',
    description='JWT support for Cromlech',
    long_description=desc(
        "README.txt",
        os.path.join("tests", "test_jwt.txt"),
        os.path.join("docs", "HISTORY.txt")
    ),
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
        'test': test_requires,
    },
)
