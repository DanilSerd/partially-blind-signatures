# partially-blind-signatures
Implementation of Partially Blind Signatures as per [Masayuki Abe and Tatsuaki Okamoto](https://www.iacr.org/archive/crypto2000/18800272/18800272.pdf)
Fully in typescript using [indutny/elliptic](https://github.com/indutny/elliptic)

**This is a POC not intended for production use.**

## Usage 

```typescript
import { Requester, Secp256k1Curve, Signer } from "partially-blind-signatures"

// Requester contacts signer with info and they agree on this.
const sharedInfo = "some shared info both signer and requester pre-agree on"

// Signer creates message 1
const privateKey = Secp256k1Curve.genKeyPair().getPrivate()
const signer = new Signer(privateKey, sharedInfo)
const publicKey = signer.getPubKey()
const message1 = signer.createMessage1()

// Requester recieves message 1 and produces message 2 using the secret message
const secret = "*****super secret message only requester knows about*******"
const requester = new Requester(publicKey, sharedInfo, secret)
const message2 = requester.createMessage2(message1)

// Signer recieves message 2 and creates message 3
const message3 = signer.createMessage3(message2)

// Requester recieves message 3 and creates the partially blind signiture
const sig = requester.createSig(message3)

// sig must now be kept sekret

// Some time passes...
// Requester connects to signer anonymously
// Requester reveals the signiture and secret message 
// Now signiture can be verified, without being tied back to original requester.
console.log(sig.verify(secret, sharedInfo, publicKey))

```

