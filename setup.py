from setuptools import setup, find_packages

setup(
    name="snekmap",
    version="0.1.0",
    author="synv3x",
    author_email="",
    description="Network reconnaissance and vulnerability assessment scanner",
    long_description=(
        "SnekMap combines nmap-style port scanning with automated CVE correlation "
        "from the NIST NVD API v2.0. It discovers live hosts, enumerates open ports "
        "and service versions, maps each service to known CVEs, and generates reports "
        "in HTML, PDF, JSON, and CSV formats. Designed for use by security analysts "
        "and penetration testers."
    ),
    url="https://github.com/synv3x/snekmap",
    py_modules=[
        "snekmap",
        "scanner",
        "cve_lookup",
        "report",
        "scanner_checks",
        "protocol_checks",
        "correlation",
    ],
    install_requires=[
        "python-nmap==0.7.1",
        "requests==2.34.2",
        "rich==15.0.0",
        "reportlab==4.5.1",
    ],
    entry_points={
        "console_scripts": [
            "snekmap=snekmap:main",
        ],
    },
    python_requires=">=3.9",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Topic :: System :: Networking :: Monitoring",
        "Intended Audience :: Information Technology",
    ],
)
