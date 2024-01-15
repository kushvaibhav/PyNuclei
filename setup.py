import setuptools

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setuptools.setup(
    name="PyNuclei",
    version="1.3",
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
    package_data={"": [".config"]},
    include_package_data=True,
    python_requires=">=3.4",
    install_requires=["PyYAML", "requests", "fake_useragent"],
)
