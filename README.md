# Pen of Midas

> Gussy it up as much as you want, Trebek, What matters is does it work?  
> - "Sean Connery" - Celebrity Jeopardy SNL s24e16

Hashing and signature verification without the Ethereum client.

## Why?

### Wallets as identity providers

Verifying signatures from Ethereum wallets is a cornerstone of Ethereum's
security. While the lion's share are transaction signatures, the mechanisms can
be used in a broad swath of cases. This library implements the keccak SHA3,
ECRecover, and a signature validator without the need for an RPC/IPC client.

### Practically, it's about DevOps

For smaller projects and demos, deploying both an app *and* the go-ethereum
node starts getting expensive. This removes some of the headache for back-end
developers and Ops when a small library will suffice.

## Usage

### byte-arrays everywhere!

All functions take `byte-array`s as inputs and return `byte-array`s. If a
failure occurs, `nil` is returned instead.

I've included `hex->bytes` and `bytes->hex` to make your lives easier.

I also solved the infamous [Prefix Issue][prefix-issue] with `hash-with-prefix`. [You're welcome][youre-welcome].

### Verify

`verify` is the dead-simple process. Give it the message, signature, and
known wallet address and it will return true or false if all three match.

```clojure
(ns your.awesome.project
  (:require [pen-of-midas.core :refer [verify hex->bytes hash-with-prefix])

(verify
  (hash-with-prefix "personal_sign message")
  (hex->bytes "0x12345deadbeaf...1c")
  "0xdeadbeaf0123456789abcdef0123456789abcdef")
; => true (we hope!)
```

### Keccak-256 (SHA3)

Pretty straightforward. Bytes in, bytes out.

```clojure
(ns your.awesome.project
  (:require [pen-of-midas.core :refer [keccak-256 bytes->hex]))

(println (-> "more than lambo memes and shard jokes"
             .getBytes
             keccak-256
             bytes->hex)
; => "0x44261e7b5d06c3d5a0b52cf40964c454ae92044aa0ff908e3c7460663b5381db"
```

### ECRecover

`ecrecover` pulls the full public key from the message and signature. This can
be passed into `key->address` to get the Ethereum wallet address.

**BEWARE!**

`ecrecover` *always* succeeds in extracting a public key, even if it's not
the correct key! Always check the key against a known wallet address, and
double-check the message payload hashes.

```clojure
(ns your.awesome.project
  (:require [pen-of-midas.core :as pen])

(def payload
  {:message "personal_sign message"
   :signature (pen/hex->bytes "0x12345deadbeaf...1c")})

(def public-key-bytes
  (pen/ecrecover
    (pen/hash-with-prefix (:message payload))
    (:signature payload))

(println (count public-key-bytes))
; => 65

(println (pen/key->address public-key-bytes))
; => "0xdeadbeaf0123456789abcdef0123456789abcdef"

;; BEWARE! Notice the missing prefix!
(-> payload
    :message
    .getBytes
    keccak-256
    (pen/ecrecover (:signature payload))
    key->address)
; => "0x368af29ca2cf40964c454ae92044aa0ff908e3c7"
```

## License

Copyright © 2018 James Leonis

Distributed under the Eclipse Public License either version 1.0 or (at
your option) any later version.

[prefix-issue]: https://github.com/ethereum/go-ethereum/issues/14794

[youre-welcome]: https://www.youtube.com/watch?v=79DijItQXMM
