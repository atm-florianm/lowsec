# Lowsec: low-security encryption

## Usage example
```sh
echo 'Hello world' | lowsec enc 'my secret key' > 'hello.txt.encrypted'
```
Now `hello.txt.encrypted` contains something that looks like gibberish.

```sh
cat 'hello.txt.encrypted' | lowsec dec 'my secret key' > 'hello.txt'
```
Now `hello.txt` contains 'Hello world'.

```python
import lowsec
secret = 'My Secret Key'.encode('utf-8')

text = '''This text should be encrypted.'''.encode('utf-8')
ciphertext = lowsec.enc(secret, text)

print(ciphertext) # gibberish

cleartext = lowsec.dec(secret, ciphertext)

print(text == cleartext)
print(cleartext.decode('utf-8')
```
