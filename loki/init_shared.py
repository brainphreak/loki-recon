#init_shared.py
# Description:
# This file, init_shared.py, is responsible for initializing and providing access to shared data across different modules in the Bjorn project.
#
# Key functionalities include:
# - Importing the `SharedData` class from the `shared` module.
# - Creating an instance of `SharedData` named `shared_data` that holds common configuration, paths, and other resources.
# - Ensuring that all modules importing `shared_data` will have access to the same instance, promoting consistency and ease of data management throughout the project.

import sys
import os

# Fix OpenSSL legacy provider issue for cryptography/paramiko
os.environ['CRYPTOGRAPHY_OPENSSL_NO_LEGACY'] = '1'

from shared import SharedData

shared_data = SharedData()
