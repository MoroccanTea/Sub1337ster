# setup.py
from setuptools import setup, find_packages

setup(
    name="Sub1337ster",  # Package name
    version="2.0.0",
    packages=find_packages(),  # Automatically find the 'sub1337ster' folder as a package
    install_requires=[
        "requests",
        "termcolor",
    ],
    entry_points={
        "console_scripts": [
            # Format: 'script_name = package.module:function'
            # This creates a 'sub1337ster' command that calls main() in Sub1337ster.py
            "sub1337ster=sub1337ster.Sub1337ster:main"
        ]
    },
    license="MIT",
    author="Hamza ESSAD",
    author_email="essadhmz@gmail.com",
    description="Concurrent subdomain enumeration with optional geolocation",
    long_description="""
Sub1337ster is a subdomain enumeration tool that checks for live subdomains 
using DNS resolution or ping, integrates geolocation lookups, and logs results 
to CSV. Supports concurrency and customizable wordlists.
""".strip(),
    long_description_content_type="text/markdown",
    url="https://github.com/MoroccanTea/Sub1337ster",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.7',
)
