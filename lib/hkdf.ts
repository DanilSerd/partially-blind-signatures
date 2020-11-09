import * as crypto from 'crypto'

const zeros = (length: number) => {
  return Buffer.alloc(length);
}

export class HKDF {
  hashAlg: string;
  hashLength: number;
  salt: Buffer;
  ikm: Buffer;
  prk: Buffer;
  constructor(hashAlg: string, ikm: Buffer, salt?: Buffer) {
    this.hashAlg = hashAlg;
    
    // create the hash alg to see if it exists and get its length
    const hash = crypto.createHash(this.hashAlg);
    this.hashLength = hash.digest().length;

    this.salt = salt || zeros(this.hashLength);
    this.ikm = ikm;

    // now we compute the PRK
    const hmac = crypto.createHmac(this.hashAlg, this.salt);
    hmac.update(this.ikm);
    this.prk = hmac.digest();
  }
  derive(info: Buffer, size: number) {
    let prev = Buffer.alloc(0);
    const output = Buffer.alloc(size);
    const num_blocks = Math.ceil(size / this.hashLength);
  
    for (var i=0; i<num_blocks; i++) {
      const hmac = crypto.createHmac(this.hashAlg, this.prk);
      const input = Buffer.concat([
        prev, 
        info, 
        Uint8Array.from([0x01 * (i+1)])
      ]);
      hmac.update(input);
      prev = hmac.digest();
      output.write(prev.toString("binary"), this.hashLength * i, this.hashLength, 'binary');
    }
    return output
  }
}