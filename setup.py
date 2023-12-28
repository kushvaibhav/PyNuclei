import setuptools

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setuptools.setup(
    name="PyNuclei",
    version="1.1",
    author="Vaibhav Kushwaha",
    author_email="vaibhavkush.007@gmail.com",
    description="PyNuclei is an unofficial python library for Nuclei Scanner.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/kushvaibhav/PyNuclei/",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    # package_dir={"": "PyNuclei"},
    # packages=setuptools.find_packages(where="PyNuclei"),
    python_requires=">=3.4",
)

