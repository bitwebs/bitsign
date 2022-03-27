'use strict'
const { test } = require('tap')
const {
  crypto_sign_verify_detached: verify,
  crypto_generichash: hash
} = require('sodium-universal')
const bitsign = require('../')()
const bencode = require('bencode')
test('keypair', async ({ is }) => {
  const { publicKey, secretKey } = bitsign.keypair()
  is(publicKey instanceof Buffer, true)
  is(publicKey.length, 32)
  is(secretKey instanceof Buffer, true)
  is(secretKey.length, 64)
})

test('salt', async ({ is, throws }) => {
  const salt = bitsign.salt()
  is(salt instanceof Buffer, true)
  is(salt.length, 32)
  is(bitsign.salt(64).length, 64)
  throws(() => bitsign.salt(15))
  throws(() => bitsign.salt(65))
})

test('salt string', async ({ is, throws }) => {
  const salt = bitsign.salt('test')
  is(salt instanceof Buffer, true)
  is(salt.length, 32)
  is(bitsign.salt(64).length, 64)
  const check = Buffer.alloc(32)
  hash(check, Buffer.from('test'))
  is(salt.equals(check), true)
  throws(() => bitsign.salt('test', 15))
  throws(() => bitsign.salt('test', 65))
})

test('signable', async ({ is, same }) => {
  const salt = bitsign.salt()
  const value = Buffer.from('test')
  same(
    bitsign.signable(value),
    bencode.encode({ seq: 0, v: value }).slice(1, -1)
  )
  same(
    bitsign.signable(value, { seq: 1 }),
    bencode.encode({ seq: 1, v: value }).slice(1, -1)
  )
  same(
    bitsign.signable(value, { salt }),
    bencode.encode({ salt, seq: 0, v: value }).slice(1, -1)
  )
})

test('signable - decodable with bencode', async ({ is, same }) => {
  const salt = bitsign.salt()
  const value = Buffer.from('test')
  const msg = bitsign.signable(value, { salt })
  const result = bencode.decode(
    Buffer.concat([Buffer.from('d'), msg, Buffer.from('e')])
  )
  is(Buffer.isBuffer(result.salt), true)
  is(Buffer.isBuffer(result.v), true)
  same(result.salt, salt)
  same(result.v, value)
  is(result.seq, 0)
})

test('signable - salt must be a buffer', async ({ throws }) => {
  throws(() => bitsign.signable(Buffer.from('test'), { salt: 'no' }), 'salt must be a buffer')
})

test('signable - salt size must be no greater than 64 bytes', async ({ throws }) => {
  throws(
    () => bitsign.signable(Buffer.from('test'), { salt: Buffer.alloc(65) }),
    'salt size must be no greater than 64 bytes'
  )
})

test('signable - value must be buffer', async ({ throws }) => {
  const keypair = bitsign.keypair()
  throws(() => bitsign.signable('test', { keypair }), 'Value must be a buffer')
})

test('signable - value size must be <= 1000 bytes', async ({ throws }) => {
  const keypair = bitsign.keypair()
  throws(
    () => bitsign.signable(Buffer.alloc(1001), { keypair }),
    'Value size must be <= 1000'
  )
})

test('sign', async ({ is }) => {
  const keypair = bitsign.keypair()
  const { publicKey } = keypair
  const salt = bitsign.salt()
  const value = Buffer.from('test')
  is(
    verify(
      bitsign.sign(value, { keypair }),
      bitsign.signable(value),
      publicKey
    ),
    true
  )
  is(
    verify(
      bitsign.sign(value, { salt, keypair }),
      bitsign.signable(value, { salt }),
      publicKey
    ),
    true
  )
  is(
    verify(
      bitsign.sign(value, { seq: 2, keypair }),
      bitsign.signable(value, { seq: 2 }),
      publicKey
    ),
    true
  )
})

test('sign - salt must be a buffer', async ({ throws }) => {
  throws(() => bitsign.sign(Buffer.from('test'), { salt: 'no' }), 'salt must be a buffer')
})

test('sign - salt size must be >= 16 bytes and <= 64 bytes', async ({ throws }) => {
  throws(
    () => bitsign.sign(Buffer.from('test'), { salt: Buffer.alloc(15) }),
    'salt size must be between 16 and 64 bytes (inclusive)'
  )
  throws(
    () => bitsign.sign(Buffer.from('test'), { salt: Buffer.alloc(65) }),
    'salt size must be between 16 and 64 bytes (inclusive)'
  )
})

test('sign - value must be buffer', async ({ throws }) => {
  const keypair = bitsign.keypair()
  throws(() => bitsign.sign('test', { keypair }), 'Value must be a buffer')
})

test('sign - options are required', async ({ throws }) => {
  throws(() => bitsign.sign('test'), 'Options are required')
})

test('sign - value size must be <= 1000 bytes', async ({ throws }) => {
  const keypair = bitsign.keypair()
  throws(
    () => bitsign.sign(Buffer.alloc(1001), { keypair }),
    'Value size must be <= 1000'
  )
})

test('sign - keypair option is required', async ({ throws }) => {
  throws(
    () => bitsign.sign(Buffer.alloc(1001), {}),
    'keypair is required'
  )
})

test('sign - keypair must have secretKey which must be a buffer', async ({ throws }) => {
  const keypair = bitsign.keypair()
  keypair.secretKey = 'nope'
  throws(
    () => bitsign.sign(Buffer.alloc(1001), { keypair }),
    'keypair.secretKey is required'
  )
  delete keypair.secretKey
  throws(
    () => bitsign.sign(Buffer.alloc(1001), { keypair }),
    'keypair.secretKey is required'
  )
})

test('cryptoSign - msg must be buffer', async ({ throws }) => {
  const keypair = bitsign.keypair()
  throws(() => bitsign.cryptoSign('test', keypair), 'msg must be a buffer')
})

test('cryptoSign - keypair is required', async ({ throws }) => {
  throws(() => bitsign.cryptoSign('test'), 'keypair is required')
})

test('cryptoSign - keypair must have secretKey which must be a buffer', async ({ throws }) => {
  const keypair = bitsign.keypair()
  keypair.secretKey = 'nope'
  throws(
    () => bitsign.cryptoSign(Buffer.alloc(1001), { keypair }),
    'keypair.secretKey is required'
  )
  delete keypair.secretKey
  throws(
    () => bitsign.cryptoSign(Buffer.alloc(1001), { keypair }),
    'keypair.secretKey is required'
  )
})

test('cryptoSign', async ({ is }) => {
  const keypair = bitsign.keypair()
  const { publicKey } = keypair
  const salt = bitsign.salt()
  const value = Buffer.from('test')
  is(
    verify(
      bitsign.cryptoSign(bitsign.signable(value), keypair),
      bitsign.signable(value),
      publicKey
    ),
    true
  )
  is(
    verify(
      bitsign.cryptoSign(bitsign.signable(value, { salt }), keypair),
      bitsign.signable(value, { salt }),
      publicKey
    ),
    true
  )
  is(
    verify(
      bitsign.cryptoSign(bitsign.signable(value, { seq: 2 }), keypair),
      bitsign.signable(value, { seq: 2 }),
      publicKey
    ),
    true
  )
})
