import os

from setuptools import find_packages
from setuptools import setup
import sys




setup(
    name='sanctum',
    version='0.0.1',
    description='sanctum',
    author="Antoine Blaud",
    author_email="antoine.blaud@gmail.com",
    setup_requires=['setuptools'],
    py_modules=['sanctum'],      
    packages=find_packages(),
    install_requires=[
    ]
)    