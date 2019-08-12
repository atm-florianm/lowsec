# Lowsec: low-security encryption

## Usage example
```sh
echo 'Hello world' | lowsec enc 'my secret key' > 'hello.txt.encrypted'
```
Now `hello.txt.encrypted` contains something that looks like gibberish.

```sh
cat 'hello.txt.encrypted' | lowsec dec 'my secret key' > 'hello.txt'
```
Now `hello.txt` contains 'Hello world'
