from setuptools import setup, find_packages

setup(
    name="ninja-api-hunter",
    version="4.0.0",
    description="Async API reconnaissance and security-assessment toolkit",
    packages=find_packages(include=["ninja_hunter", "ninja_hunter.*"]),
    install_requires=["aiohttp>=3.9.0", "PyYAML>=6.0"],
    python_requires=">=3.8",
    entry_points={
        "console_scripts": [
            "ninja-hunter=ninja_hunter.cli:main",
        ],
    },
)
