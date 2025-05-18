from setuptools import setup, find_packages

setup(
    name="symbolic_modeling",
    version="0.1",
    packages=find_packages(),
    install_requires=[
        "z3-solver>=4.8.12",
    ],
    entry_points={
        'console_scripts': [
            'symbolic-modeling=symbolic_modeling.main:main',
        ],
    },
)