from setuptools import setup

setup(
   name="cis_publishers",
   version="1.1.0",
   description="The various CIS publishers",
   author="April King",
   author_email="april@mozilla.com",
   packages=["cis_publishers"],
   install_requires=[
       "boto3",
       "python-jose[cryptography]",
       "requests",
   ],
)
