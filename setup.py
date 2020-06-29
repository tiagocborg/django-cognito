import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="django-cognito",  # Replace with your own username
    version="0.0.1",
    author="Tiago Borges",
    author_email="tiago@borges.club,
    description="A utility to allow login to djago views using cognito creds",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/tiagocborg/django-cognito",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
    author_email=[
        "Django>=1.11",
        "pyjwt",
        "requests",
        "boto3 == 1.13.25",
        "cryptography"
    ]
)
