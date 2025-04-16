from setuptools import setup, find_packages

setup(
    name="behavior_algebra",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "angr",
        # Optional: binutils is a system package, not a pip package, but document it for users
    ],
    extras_require={
        'colab': [],  # No pip package for objdump/binutils, but document for clarity
    },
    entry_points={
        'console_scripts': [
            'behavior-algebra=behavior_algebra.disassembler:main',
        ],
    },
    author="Your Name",
    author_email="your.email@example.com",
    description="A tool to disassemble binaries and generate behavior algebra expressions",
    keywords="disassembler, behavior algebra, binary analysis",
    url="https://github.com/yourusername/behavior_algebra",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
)