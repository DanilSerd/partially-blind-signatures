import * as h from 'hash.js'
import * as ell from 'elliptic'
import { Secp256k1Curve } from '.';
import BN from 'bn.js';

const zeros = (length: number): number[] => {
  return new Array(length).fill(0)
}

class HKDF {
  hashAlg: Sha256;
  hashLength: number;
  prk: number[];
  constructor(hashAlg: Sha256, ikm: string) {
    this.hashAlg = hashAlg;

    this.hashLength = hashAlg.outSize;

    const hmac = h.hmac(this.hashAlg, zeros(this.hashLength));
    hmac.update(ikm);
    this.prk = hmac.digest();
  }
  derive(info: string, size: number) {
    // @ts-ignore We don't need enc here
    let infoArray = h.utils.toArray(info)
    let prev: number[] = new Array(0);
    let output: number[] = [];
    const num_blocks = Math.ceil(size / this.hashLength);
  
    for (var i=0; i<num_blocks; i++) {
      const hmac = h.hmac(this.hashAlg, this.prk);
      const input = [
        ...prev,
        ...infoArray,
        0x01 * (i+1)
      ]
      hmac.update(input);
      prev = hmac.digest();
      output = [
        ...output,
        ...prev
      ];
    }
    return output
  }
}

export const hashToPoint = (info: string, curve: ell.ec = Secp256k1Curve) => {
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