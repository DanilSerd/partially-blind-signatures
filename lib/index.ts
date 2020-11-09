import { randomBytes } from 'crypto'
import * as e from 'elliptic'
import BN from 'bn.js'
import * as hash from 'hash.js'
import { HKDF } from './hkdf'

const shredInfo = "hello"

// @ts-ignore
const curve = e.curves.secp256k1.curve as e.curve.short

const generateRandom256Num = () => {
  return new BN("0x" + randomBytes(32))
}

const insecureHashToPoint = (info: string, curve: e.curve.short) => {
  const infoHashed = new HKDF(
    "sha256", 
    Buffer.from(info, 'utf8')
  ).derive(
    Buffer.from("TOCURVE", 'utf8'),
    32
  )

  const x = new BN(infoHashed).umod(curve.p)
  
  return curve.pointFromX(x)
}

class Signer {
  private sk: BN
  private info: string
  private curve: e.curve.short
  private u: BN
  private s: BN
  private d: BN
  constructor(sk: BN, info: string) {
    this.sk = sk
    this.info = info
    this.curve = curve
    this.u = generateRandom256Num().umod(this.curve.n)
    this.s = generateRandom256Num().umod(this.curve.n)
    this.d = generateRandom256Num().umod(this.curve.n)
  }

}