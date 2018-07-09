==============================
    Python NtruEncrypt Wrapper
==============================

|CircleciImage|_ |LicenseImage|_ |PrImage|_

.. |CircleciImage| image:: https://circleci.com/gh/SnowyCoder/ntruencryptlib-wrapper/tree/master.svg?style=shield
.. _CircleciImage: https://circleci.com/gh/SnowyCoder/ntruencryptlib-wrapper/tree/master

.. |LicenseImage| image:: https://img.shields.io/badge/License-MIT-blue.svg?style=flat
.. _LicenseImage: https://github.com/SnowyCoder/ntruencryptlib-wrapper/blob/master/LICENSE.md

.. |PrImage| image:: https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat
.. _PrImage: http://makeapullrequest.com/


**Encrypt your data using NTRU encryption**

----

----------
    About:
----------

ntruencrypt is a python module that wraps libntruencrypt in a developer-friendly way.

----

----------------------------
    What is libntruencrypt?:
----------------------------

`libtruencrypt <https://github.com/NTRUOpenSourceProject/NTRUEncrypt>`_ is the main implementation of the NTRU encryption algorithm.

The NTRU Encryption algorithm is a lattice-based asymmetric encryption algorithm though for the post-quantum encryption.

----

------------------------
    Install ntruencrypt:
------------------------

::

    git clone https://github.com/SnowyCoder/ntruencryptlib-wrapper
    cd ntruencryptlib-wrapper
    python3 setup.py install


----

------------------------
    System Requirements:
------------------------

* Linux or Mac (for now)
* Autotools and compilation tools
* Python3

----

-----------------------
    Basic Usage Example
-----------------------

::

    import ntruencrypt

    key_pair = ntruencrypt.create_keys()

    pub_key, prv_key = key_pair

    # Encrypt some data
    encrypted_data = pub_key.encrypt("Example Data")
    # And decrypt it
    decrypted_data = prv_key.decrypt(encrypted_data)
    print(decrypted_data)


You can find more examples in the tests
