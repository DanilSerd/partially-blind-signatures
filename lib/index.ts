import { randomBytes } from 'crypto'
import * as ell from 'elliptic'
import BN from 'bn.js'
import * as hash from 'hash.js'
import { HKDF } from './hkdf'

// @ts-ignore
const curve = ell.curves.secp256k1.curve as ell.curve.short

const generateRandom256Num = () => {
  return new BN(randomBytes(32))
}

const insecureHashToPoint = (info: string, curve: ell.curve.short) => {
  const hkdf = new HKDF(
    "sha256", 
    Buffer.from(info, 'utf8')
  )

  for (let i = 0x0; true; i++) {
    const infoHashed = hkdf.derive(
      Buffer.from(i.toString(), "utf8"),
      32
    )
    try {
      return curve.pointFromX(new BN(infoHashed).umod(curve.p)) 
    } catch {
      continue
    }
  }
}

interface ABMessage {
  a: ell.curve.base.BasePoint
  b: ell.curve.base.BasePoint
}

interface RCSDMessge {
  r: BN
  c: BN
  s: BN
  d: BN
}

type EMessage = BN

interface Signiture {
  p: BN
  w: BN
  o: BN
  g: BN
}

class Signer {
  private sk: BN
  private curve: ell.curve.short
  private u: BN
  private s: BN
  private d: BN
  infoBase: ell.curve.base.BasePoint
  constructor(sk: BN, info: string) {
    this.sk = sk
    this.curve = curve
    this.u = generateRandom256Num().umod(this.curve.n)
    this.s = generateRandom256Num().umod(this.curve.n)
    this.d = generateRandom256Num().umod(this.curve.n)
    this.infoBase = insecureHashToPoint(info, this.curve)
  }

  createAB(): ABMessage {
    return {
      a: this.curve.g.mul(this.u),
      b: this.curve.g.mul(this.s).add(this.infoBase.mul(this.d))
    }
  }

  createRCSD(e: BN): RCSDMessge {
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
  private curve: ell.curve.short
  private message: string
  infoBase: ell.curve.base.BasePoint
  private t1: BN
  private t2: BN
  private t3: BN
  private t4: BN
  constructor(signerPublicKey: ell.curve.base.BasePoint, info: string, message: string) {
    this.signerPublicKey = signerPublicKey
    this.message = message
    this.curve = curve
    this.infoBase = insecureHashToPoint(info, this.curve)
    this.t1 = generateRandom256Num().umod(this.curve.n)
    this.t2 = generateRandom256Num().umod(this.curve.n)
    this.t3 = generateRandom256Num().umod(this.curve.n)
    this.t4 = generateRandom256Num().umod(this.curve.n)
  }

  createE(m: ABMessage): EMessage {
    const alpha = m.a.add(this.curve.g.mul(this.t1)).add(this.signerPublicKey.mul(this.t2))
    const bravo = m.b.add(this.curve.g.mul(this.t3)).add(this.infoBase.mul(this.t4))
    console.log("Construction")
    console.log("a:  " + alpha.getX().toBuffer().toString('hex'))
    console.log("b:  " + bravo.getX().toBuffer().toString('hex'))
    console.log("z:  " + this.infoBase.getX().toBuffer().toString('hex'))
    console.log("message: " + Buffer.from(this.message, "utf8").toString('hex'))
    const echo = Buffer.concat([
      alpha.getX().toBuffer(),
      bravo.getX().toBuffer(),
      this.infoBase.getX().toBuffer(),
      Buffer.from(this.message, "utf8")
    ])
    console.log(new BN(hash.sha256().update(echo).digest()).toString('hex'))
    
    return new BN(hash.sha256().update(echo).digest())
      .sub(this.t2)
      .sub(this.t4)
      .umod(this.curve.n)
  }

  createSig(m: RCSDMessge): Signiture {
    return {
      p: m.r.add(this.t1).umod(this.curve.n),
      w: m.c.add(this.t2).umod(this.curve.n),
      o: m.s.add(this.t3).umod(this.curve.n),
      g: m.d.add(this.t4).umod(this.curve.n)
    }
  }
}

const validateSig = (sig: Signiture, message: string, info: string, signerPublicKey: ell.curve.base.BasePoint, curve: ell.curve.short) => {
  const z = insecureHashToPoint(info, curve)

  console.log("")
  console.log("Check")
  console.log("a: " + curve.g.mul(sig.p).add(signerPublicKey.mul(sig.w)).getX().toBuffer().toString('hex'))
  console.log("b: " + curve.g.mul(sig.o).add(z.mul(sig.g)).getX().toBuffer().toString('hex'))
  console.log("z: " + z.getX().toBuffer().toString('hex'))
  console.log("message: " + Buffer.from(message, "utf8").toString('hex'))

  const completeConstruction = Buffer.concat([
    curve.g.mul(sig.p).add(signerPublicKey.mul(sig.w)).getX().toBuffer(),
    curve.g.mul(sig.o).add(z.mul(sig.g)).getX().toBuffer(),
    z.getX().toBuffer(),
    Buffer.from(message, "utf8")
  ])

  const left = new BN(hash.sha256().update(completeConstruction).digest())
  console.log(left.toString('hex'))
  const right = sig.w.add(sig.g).mod(curve.n)
  console.log("")
  console.log(left.toString('hex'))
  console.log(right.toString('hex'))

  return left.eq(right)

}



const s = new Signer(generateRandom256Num(), "info")
const r = new Requester(s.getPubKey(), 'info', 'super secret message')

const ab = s.createAB()
const e = r.createE(ab)
const rcsd = s.createRCSD(e)
const sig = r.createSig(rcsd)

console.log(
  validateSig(sig, 'super secret message', "info", s.getPubKey(), curve)
)
