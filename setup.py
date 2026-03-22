from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="neuro-red-kit",
    version="0.1.0-alpha",
    author="Chao Liu (Sol)",
    author_email="neuro-red-kit@proton.me",
    description="A Red Teaming Toolkit for Neural-Agent Hybrid Systems",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/helianbobo/neuro-red-kit",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Intended Audience :: Science/Research",
        "Topic :: Security",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    python_requires=">=3.9",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "neuro-red=neuro_red_kit.cli:main",
        ],
    },
)
