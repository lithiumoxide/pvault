# pvault
A simple username and password safe written in Python3

## Usage
At the command line:

```
python3 pvault.py [list|add|retrieve]
```

Alternatively, make the file executable (`chmod +x pvault.py`) and run:

```
./pvault.py [list|add|retrieve]
```

* **list** - lists all aliases in the password vault
* **add** - add a uername/password to the password vault
* **retrieve** - retrieve a username/password from the vault

Add an alias for the username/password to use as an identifier. The vault password is used to generate a key to encrypt your username and password. This does not have to be the same password for each entry: you _can_ use a different vault password for each entry, as each one is encrypted individually.

### Dependencies
Requires:
* Python3.6+
* cryptography

## Disclaimer
This was written for learning purposes only. The author accepts no liability for using this tool, and all risk lies on the end user.
