import os

from setuptools import find_packages, setup

# Try to load the version from a datafile in the package
package_version = "4.0.0.dev0"
package_version_path = os.path.join(os.path.dirname(__file__), "assemblyline_v4_service", "VERSION")
if os.path.exists(package_version_path):
    with open(package_version_path) as package_version_file:
        package_version = package_version_file.read().strip()

# read the contents of your README file
this_directory = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(this_directory, "README.md"), encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="assemblyline-v4-service",
    version=package_version,
    description="Assemblyline 4 - Service base",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/CybercentreCanada/assemblyline-v4-service/",
    author="CCCS Assemblyline development team",
    author_email="assemblyline@cyber.gc.ca",
    license="MIT",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Topic :: Software Development :: Libraries",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    keywords="assemblyline automated malware analysis gc canada cse-cst cse cst cyber cccs",
    packages=find_packages(
        exclude=[
            "test/*",
            "docker/*",
            "assemblyline_result_sample_service/*",
            "assemblyline_extra_feature_service/*",
        ]
    ),
    install_requires=[
        "assemblyline",
        "assemblyline-core",
        "cart",
        "fuzzywuzzy",
        "pefile",
        "pillow==10.2.0",
        "python-Levenshtein",
        "regex",
    ],
    extras_require={
        "updater": [
            "gunicorn[gevent]",
            "flask",
            "gitpython",
            "git-remote-codecommit",
            "psutil",
        ]
    },
    package_data={
        "": [
            "*.xml",
            "VERSION",
        ],
        "assemblyline_v4_service": ["py.typed"],
    },
)
