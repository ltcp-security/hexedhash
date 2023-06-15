# hexedhash
A module to create a hash from text by translating the text into a hex, adding a "salt" and trimming out the extra parts.

### How to install
Open your console and paste it
```
pip install hexedhash
```

### How to use
Using the module is very easy. Here are a couple of examples.
#### First example
```python
from hexedhash import Hasher
hash01 = Hasher(prefix="ltcp", salt="hash::189dj")

if __name__ == "__main__":
    print(hash01.makehash("Hello world!"))
```
Output:
```
ltcp[3a6f3a203177386f]
```

#### Second example
```python
from hexedhash import Hasher
if __name__ == "__main__":
    print(Hasher().makehash("Hello world!"))
```
Output:
```
ltcp[5f6f73206577636f]
```
