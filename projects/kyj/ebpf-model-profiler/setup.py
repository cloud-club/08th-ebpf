# setup.py - Package configuration for eBPF Model Serving Latency Profiler

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="ebpf-model-profiler",
    version="0.1.0",
    author="CloudClub",
    author_email="example@cloudclub.com",
    description="eBPF-based latency profiler for model serving APIs",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/cloudclub/ebpf-model-profiler",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: System :: Monitoring",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: POSIX :: Linux",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "ebpf-profiler=src.cli:cli",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)
