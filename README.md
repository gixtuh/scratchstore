# ScratchStore

**ScratchStore (inspired by [scratchattach](https://github.com/TimMcCool/scratchattach)) is a cloud data store/database engine which lets you write anything into a data store file using Python and Scratch with the power of cloud variables.**

![icon](https://raw.githubusercontent.com/gixtuh/scratchstore/refs/heads/main/icon.svg)

[![Static Badge](https://img.shields.io/badge/Python_version-v1.2.0-blue?style=flat-square)](https://pypi.org/project/scratchstore/) ![PyPI Python Version](https://img.shields.io/pypi/pyversions/scratchstore?style=flat-square)
![GitHub Downloads (specific asset, all releases)](https://img.shields.io/github/downloads/gixtuh/scratchstore/ScratchStore.Template.sb3?style=flat-square) ![PyPI Downloads](https://img.shields.io/pypi/dm/scratchstore)



## Installation
```bash
pip install scratchstore
```
... is all that's required to install ScratchStore

## Usage
Here's a tiny example program:
```python
import scratchstore

file = scratchstore.add("store", "./store.json")
scratchstore.connection.setup(1439699440, "Policerdarm111", "1234567890") # Not my actual password!
scratchstore.connection.use([file])
scratchstore.start(True, True)
```
<hr/>

### Basic commands:
- `scratchstore.add` - Creates or uses an already existing database

- `scratchstore.connection` - Controls the connection with Scratch's services

    - `.connection.setup` - Sets up the connection with the project and authenticates with your Scratch account

    - `.connection.use` - Chooses which databases should it include before starting

- `scratchstore.start` - Starts the ScratchStore connection

<hr />

**ScratchStore is currently under active development, expect bugs!**
