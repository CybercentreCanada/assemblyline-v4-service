import os

from setuptools import setup, find_packages

# For development and local builds use this version number, but for real builds replace it
# with the tag found in the environment
package_version = "4.0.0.dev0"
for variable_name in ['BITBUCKET_TAG']:
    package_version = os.environ.get(variable_name, package_version)
    package_version = package_version.lstrip('v')

# read the contents of your README file
from os import path
this_directory = path.abspath(path.dirname(__file__))
with open(path.join(this_directory, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name="assemblyline-v4-service",
    version=package_version,
    description="Assemblyline (v4) automated malware analysis framework - v4 Service components.",
    long_description=long_description,
    long_description_content_type='text/markdown',
    url="https://bitbucket.org/cse-assemblyline/alv4_service/",
    author="CCCS Assemblyline development team",
    author_email="assemblyline@cyber.gc.ca",
    license="MIT",
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Libraries',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3.7',
    ],
    keywords="assemblyline malware gc canada cse-cst cse cst cyber cccs",
    packages=find_packages(exclude=['test/*', 'docker/*', 'assemblyline_result_sample_service/*']),
    install_requires=[
        'assemblyline',
        'assemblyline-core',
        'fuzzywuzzy',
        'python-Levenshtein',
    ],
    package_data={
        '': [
            "*.xml",
        ]
    }
)
