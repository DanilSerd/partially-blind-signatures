import * as hash from 'hash.js'

const zeros = (length: number): number[] => {
  return new Array(length).fill(0)
}

export class HKDF {
  hashAlg: Sha256;
  hashLength: number;
  prk: number[];
  constructor(hashAlg: Sha256, ikm: string) {
    this.hashAlg = hashAlg;

    this.hashLength = hashAlg.outSize;

    const hmac = hash.hmac(this.hashAlg, zeros(this.hashLength));
    hmac.update(ikm);
    this.prk = hmac.digest();
  }
  derive(info: string, size: number) {
    // @ts-ignore We don't need enc here
    let infoArray = hash.utils.toArray(info)
    let prev: number[] = new Array(0);
    let output: number[] = [];
    const num_blocks = Math.ceil(size / this.hashLength);
  
    for (var i=0; i<num_blocks; i++) {
      const hmac = hash.hmac(this.hashAlg, this.prk);
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