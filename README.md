# pyDeconcrete

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/simonecris/pyDeconcrete/blob/main/LICENSE)
[![Python](https://img.shields.io/badge/python-3.8%2B-cactus.svg)](https://www.python.org/downloads/)


pyDeconcrete is a proof of concept tool that allows to decrypt `.pye` files encrypted 
using `pyconcrete` using the most secure "Full Encryption" method (AES 128 bit).

--------------

## Features

- Given the generated `pyconcrete` executable and the encrypted `.pye` file,
it returns the decrypted `.pyc` file.
- Easy to use with simple command-line interface.
- Only supports Windows `.exe` (Linux is WIP)

## Installation

* Clone the repository:

 ```sh
 git clone https://github.com/simonecris/pyDeconcrete.git
 cd pyDeconcrete
 ```

Make sure you have Python 3.8+ installed. You can download Python from the [official website](https://www.python.org/downloads/).

## Usage

* To use pyDeconcrete, run the following command:

```sh
python pyDeconcrete.py <pyconcrete.exe> <main.pye>
```

* To disassemble the output `.pyc` file into a source `.py`, you need a **disassembler**. 
If you are using Python up to 3.10, [pycdc](https://github.com/zrax/pycdc/) is a great choice.

## References

[pyconcrete](https://github.com/Falldog/pyconcrete),
[Ghidra](https://github.com/NationalSecurityAgency/ghidra)