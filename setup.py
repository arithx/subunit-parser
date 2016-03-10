"""
Copyright 2015-2016 Rackspace

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

from setuptools import setup, find_packages

setup(
    name='subunit-parser',
    version='0.0.1',
    description='Outputs all HTTP calls a given test made that were logged.',
    author='Stephen Lowrie',
    author_email='stephen.lowrie@rackspace.com',
    url='https://github.com/arithx/subunit-parser',
    packages=find_packages(exclude=('tests*', 'docs')),
    install_requires=open('requirements.txt').read(),
    license=open('LICENSE').read(),
    classifiers=(
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Natural Language :: English',
        'License :: Other/Proprietary License',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.7',
    ),
    entry_points={
        'console_scripts': [
            ('subunit-describe-calls = subunit_parser.'
             'describe_calls:entry_point')]})
