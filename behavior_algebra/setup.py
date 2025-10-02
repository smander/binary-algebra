from setuptools import setup, find_packages

setup(
    name="behavior_algebra",
    version="0.2.0",
    packages=find_packages(),
    install_requires=[],
    extras_require={},
    entry_points={
        'console_scripts': [
            'behavior-algebra=behavior_algebra.disassembler:main',
        ],
    },
    author="Your Name",
    author_email="your.email@example.com",
    description="Dyninst-backed disassembler with behavior algebra and CFG exports",
    keywords="dyninst, disassembler, behavior algebra, binary analysis",
    url="https://github.com/yourusername/behavior_algebra",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
)
