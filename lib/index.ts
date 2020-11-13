import * as ell from 'elliptic'
import BN from 'bn.js'
import * as hash from 'hash.js'
import { hashToPoint } from './hkdf'

export const Secp256k1Curve = new ell.ec('secp256k1')

export interface Message1 {
  a: ell.curve.base.BasePoint
  b: ell.curve.base.BasePoint
}

export type Message2 = BN

export interface Message3 {
  r: BN
  c: BN
  s: BN
  d: BN
}

export class Signiture {
  constructor(public p: BN, public w: BN, public o: BN, public g: BN, public curve: ell.ec = Secp256k1Curve) {}

  verify(msg: string, info: string, pubKey: ell.curve.base.BasePoint): boolean {
    const curve = this.curve.curve as ell.curve.base
    if (!curve.validate(pubKey))
      throw new Error('Invalid public key');
    const z = hashToPoint(info)
    const m = new BN(hash.sha256().update(msg).digest())
  
    const completeConstruction = 
      curve.g.mul(this.p).add(pubKey.mul(this.w)).getX()
        .or(curve.g.mul(this.o).add(z.mul(this.g)).getX())
        .or(z.getX())
        .or(m)
  
    const right = new BN(hash.sha256().update(completeConstruction).digest())
    const left = this.w.add(this.g).mod(curve.n)

    return left.eq(right)
  }

}

export class Signer {
  private sk: BN
  private curve: ell.curve.base
  private u: BN
  private s: BN
  private d: BN
  infoBase: ell.curve.base.BasePoint
  constructor(sk: BN, info: string, curve: ell.ec = Secp256k1Curve) {
    this.sk = sk
    this.curve = curve.curve as ell.curve.base
    this.u = curve.genKeyPair().getPrivate()
    this.s = curve.genKeyPair().getPrivate()
    this.d = curve.genKeyPair().getPrivate()
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

export class Requester {
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
    this.t1 = curve.genKeyPair().getPrivate()
    this.t2 = curve.genKeyPair().getPrivate()
    this.t3 = curve.genKeyPair().getPrivate()
    this.t4 = curve.genKeyPair().getPrivate()
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