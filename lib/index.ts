import * as ell from 'elliptic'
import BN from 'bn.js'
import * as hash from 'hash.js'
import { HKDF } from './hkdf'

const Secp256k1Curve = new ell.ec('secp256k1')

const hashToPoint = (info: string, curve: ell.ec = Secp256k1Curve) => {
  const crv = curve.curve as ell.curve.short
  const hkdf = new HKDF(
    Secp256k1Curve.hash,
    info
  )

  for (let i = 0; i < 1000; i++) {
    const infoHashed = hkdf.derive(
      i.toString(),
      32
    )
    try {
      return crv.pointFromX(new BN(infoHashed).umod(crv.p)) 
    } catch {
      continue
    }
  }
  throw Error("Couldn't find a point")
}

interface Message1 {
  a: ell.curve.base.BasePoint
  b: ell.curve.base.BasePoint
}

type Message2 = BN

interface Message3 {
  r: BN
  c: BN
  s: BN
  d: BN
}


class Signiture {
  constructor(public p: BN, public w: BN, public o: BN, public g: BN, public curve: ell.ec = Secp256k1Curve) {}

  verify(msg: string, info: string, pubKey: ell.curve.base.BasePoint) {
    const curve = this.curve.curve as ell.curve.base
    if (!curve.validate(pubKey))
      throw new Error('Invalid public key');
    const z = hashToPoint(info)
    const m = new BN(hash.sha256().update(msg).digest())
  
    const completeConstruction = 
      curve.g.mul(sig.p).add(pubKey.mul(sig.w)).getX()
        .or(curve.g.mul(sig.o).add(z.mul(sig.g)).getX())
        .or(z.getX())
        .or(m)
  
    const right = new BN(hash.sha256().update(completeConstruction).digest())
    const left = sig.w.add(sig.g).mod(curve.n)

    return left.eq(right)
  }

}

class Signer {
  private sk: BN
  private curve: ell.curve.base
  private u: BN
  private s: BN
  private d: BN
  infoBase: ell.curve.base.BasePoint
  constructor(sk: BN, info: string, curve: ell.ec = Secp256k1Curve) {
    this.sk = sk
    this.curve = curve.curve as ell.curve.base
    this.u = Secp256k1Curve.genKeyPair().getPrivate()
    this.s = Secp256k1Curve.genKeyPair().getPrivate()
    this.d = Secp256k1Curve.genKeyPair().getPrivate()
    this.infoBase = hashToPoint(info, curve)
  }

  createMessage1(): Message1 {
    return {
      a: this.curve.g.mul(this.u),
      b: this.curve.g.mul(this.s).add(this.infoBase.mul(this.d))
    }
  }

  createMessage3(e: Message2): Message3 {
    const c = e.sub(this.d).umod(this.curve.n)
    return {
      s: this.s,
      d: this.d,
      c: c,
      r: this.u.sub(c.mul(this.sk)).umod(this.curve.n)
    }
  }

  getPubKey(): ell.curve.base.BasePoint {
    return this.curve.g.mul(this.sk)
  }
}

class Requester {
  private signerPublicKey: ell.curve.base.BasePoint
  private curve: ell.curve.base
  private _eccrv: ell.ec
  private message: string
  private infoBase: ell.curve.base.BasePoint
  private t1: BN
  private t2: BN
  private t3: BN
  private t4: BN
  constructor(signerPublicKey: ell.curve.base.BasePoint, info: string, message: string, curve: ell.ec = Secp256k1Curve) {
    this.signerPublicKey = signerPublicKey
    this.message = message
    this.curve = curve.curve as ell.curve.base
    this._eccrv = curve
    this.infoBase = hashToPoint(info, this._eccrv)
    this.t1 = Secp256k1Curve.genKeyPair().getPrivate()
    this.t2 = Secp256k1Curve.genKeyPair().getPrivate()
    this.t3 = Secp256k1Curve.genKeyPair().getPrivate()
    this.t4 = Secp256k1Curve.genKeyPair().getPrivate()
  }

  createMessage2(m: Message1): Message2 {
    const alpha = m.a.add(this.curve.g.mul(this.t1)).add(this.signerPublicKey.mul(this.t2))
    const bravo = m.b.add(this.curve.g.mul(this.t3)).add(this.infoBase.mul(this.t4))
    const echo = alpha.getX()
      .or(bravo.getX())
      .or(this.infoBase.getX())
      .or(new BN(hash.sha256().update(this.message).digest()))
    
    return new BN(hash.sha256().update(echo).digest())
      .sub(this.t2)
      .sub(this.t4)
      .umod(this.curve.n)
  }

  createSig(m: Message3): Signiture {
    return new Signiture(
      m.r.add(this.t1).umod(this.curve.n),
      m.c.add(this.t2).umod(this.curve.n),
      m.s.add(this.t3).umod(this.curve.n),
      m.d.add(this.t4).umod(this.curve.n),
      this._eccrv
    )
  }
}


const s = new Signer(Secp256k1Curve.genKeyPair().getPrivate(), "info")
const r = new Requester(s.getPubKey(), 'info', 'super secret message')

const ab = s.createMessage1()
const e = r.createMessage2(ab)
const rcsd = s.createMessage3(e)
const sig = r.createSig(rcsd)

console.log(
  sig.verify('super secret message', "info", s.getPubKey())
)
