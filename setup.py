from setuptools import setup, find_packages

setup(
    name="security-toolkit",
    version="1.0.0",
    packages=find_packages(),
    install_requires=["requests"],
    entry_points={
        "console_scripts": [
            "security-toolkit=security_toolkit.cli:main"
        ]
    },
    author="Pratik Dagar",
    description="Free security toolkit for students and startups",
    python_requires=">=3.8",
)
