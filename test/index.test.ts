import { Requester, Secp256k1Curve, Signer } from "../lib"

test("Creates a valid signiture", () => {
  const sharedInfo = "some shared info both signer and requester agree on"
  const secret = "*****super secret message only requester knows about*******"

  const s = new Signer(Secp256k1Curve.genKeyPair().getPrivate(), sharedInfo)
  const r = new Requester(s.getPubKey(), sharedInfo, secret)

  const ab = s.createMessage1()
  const e = r.createMessage2(ab)
  const rcsd = s.createMessage3(e)
  const sig = r.createSig(rcsd)

  expect(sig.verify(secret, sharedInfo, s.getPubKey())).toBe(true)
})