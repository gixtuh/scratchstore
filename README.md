# ScratchStore

**ScratchStore (inspired by [scratchattach](https://github.com/TimMcCool/scratchattach)) is a cloud data store/database engine which lets you write anything into a data store file using Python and Scratch with the power of cloud variables.**

![icon](https://raw.githubusercontent.com/gixtuh/scratchstore/refs/heads/main/icon.svg)

![PyPI Version](https://img.shields.io/pypi/v/scratchstore)
![GitHub repo size](https://img.shields.io/github/repo-size/gixtuh/scratchstore)
![GitHub commit activity](https://img.shields.io/github/commit-activity/w/gixtuh/scratchstore)

![PyPI Downloads](https://img.shields.io/pypi/dm/scratchstore)
![PyPI License](https://img.shields.io/pypi/l/scratchstore)



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
***The documentation about the backend code can be found [here](https://github.com/gixtuh/scratchstore/wiki/Backend)***

***The .sb3 template can be found [here](https://github.com/gixtuh/scratchstore/releases)***
<hr/>

### Basic commands:
- `scratchstore.add` - Creates or uses an already existing database

- `scratchstore.connection` - Controls the connection with Scratch's services

    - `.connection.setup` - Sets up the connection with the project and authenticates with your Scratch account

    - `.connection.use` - Chooses which databases should it include before starting

- `scratchstore.start` - Starts the ScratchStore connection

<hr />

**ScratchStore is currently under active development, expect bugs!**
