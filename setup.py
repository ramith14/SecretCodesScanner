from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="secret-scanner",
    version="1.0.0",
    author="Security Tools",
    description="A security tool to detect exposed secrets in files and repositories",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    install_requires=[
        "pyyaml>=6.0",
        "requests>=2.31.0",
        "gitpython>=3.1.40",
        "click>=8.1.7",
        "colorama>=0.4.6",
        "pygments>=2.16.1",
    ],
    entry_points={
        "console_scripts": [
            "secret-scanner=secret_scanner.cli:main",
        ],
    },
)
