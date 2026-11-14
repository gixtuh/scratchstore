# scratchstore

**ScratchStore (inspired by the word "data store") is a cloud data store/database engine which lets you write anything into a data store file using Python and Scratch with the power of cloud variables.**

![PyPI Python Version](https://img.shields.io/pypi/pyversions/scratchstore)


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

- `scratchstore.start` - Starts the ScratchStore service

<hr />

**ScratchStore is currently under active development, expect bugs!**