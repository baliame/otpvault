"""A setuptools based setup module.
See:
https://packaging.python.org/guides/distributing-packages-using-setuptools/
https://github.com/pypa/sampleproject
"""

# Always prefer setuptools over distutils
from setuptools import setup, find_packages

setup(
    name="otpvault",
    url="https://github.com/baliame/otpvault",
    version="1.0.0",
    description="OTP Vault",
    author="baliame",
    author_email="akos.toth@cheppers.com",  # Optional
    classifiers=[  # Optional
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3 :: Only",
    ],
    package_dir={"": "src"},  # Optional
    packages=find_packages(where="src"),  # Required
    python_requires=">=3.8, <4",
    install_requires=[
        "pyotp",
        "cryptography==39.0.2",
    ],
    entry_points={  # Optional
        "console_scripts": ["otpvault=otpvault:main"],
    },
)
