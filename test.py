from module import *

assert(generate_public_key(0x7A929ADE789BB9BE10ED359DD39A72C11B60961F49397EEE1D19CE9891EC3B28, base_parameters_1) == (0x7F2B49E270DB6D90D8595BEC458B50C58585BA1D4E9B788F6689DBD8E56FD80B, 0x26F1B489D6701DD185C8413A977B3CBBAF64D1C593D26627DFFB101A87FF77DA))
assert(generate_public_key(0xBA6048AADAE241BA40936D47756D7C93091A0E8514669700EE7508E508B102072E8123B2200A0563322DAD2827E2714A2636B7BFD18AADFC62967821FA18DD4, base_parameters_2) == (0x115DC5BC96760C7B48598D8AB9E740D4C4A85A65BE33C1815B5C320C854621DD5A515856D13314AF69BC5B924C8B4DDFF75C45415C1D9DD9DD33612CD530EFE1, 0x37C7C90CD40B0F5621DC3AC1B751CFA0E2634FA0503B3D52639F5D7FB72AFD61EA199441D943FFE7F0C70A2759A3CDB84C114E1F9339FDF27F35ECA93677BEEC))

assert(generate_common_KEK(0xABACABA, generate_public_key(0xABACABADABA, base_parameters_1), base_parameters_1) == generate_common_KEK(0xABACABADABA, generate_public_key(0xABACABA, base_parameters_1), base_parameters_1))
assert(generate_common_KEK(0xABACABA, generate_public_key(0xABACABADABA, base_parameters_2), base_parameters_2) == generate_common_KEK(0xABACABADABA, generate_public_key(0xABACABA, base_parameters_2), base_parameters_2))

assert(GOST34112012H256(int(0x323130393837363534333231303938373635343332313039383736353433323130393837363534333231303938373635343332313039383736353433323130).to_bytes(63, 'big')) == int(0x00557be5e584fd52a449b16b0251d05d27f94ab76cbaa6da890b59d8ef1e159d).to_bytes(64, 'big'))
assert(GOST34112012H256(int(0xfbe2e5f0eee3c820fbeafaebef20fffbf0e1e0f0f520e0ed20e8ece0ebe5f0f2f120fff0eeec20f120faf2fee5e2202ce8f6f3ede220e8e6eee1e8f0f2d1202ce8f0f2e5e220e5d1).to_bytes(72, 'big')) == int(0x508f7e553c06501d749a66fc28c6cac0b005746d97537fa85d9e40904efed29d).to_bytes(64, 'big'))

msg = 'Hello world! This is secret information: 0123456789.'.encode()
CEK = '01234567890123456789012345678901'.encode()
IV = '01234567'.encode()
assert(cipher_feedback_mode_decode(cipher_feedback_mode_encode(msg, CEK, IV), CEK, IV) == msg)

def to_int(msg):
  res = 0
  for i in range(len(msg)):
      res += (2**(8 * i)) * msg[-i-1]
  return res

assert(to_int(GOST2814789ECB_decode(GOST2814789ECB_encode(int(0x1001011011110000).to_bytes(32, 'big'), int(0x1001011000001111).to_bytes(32,'big')), int(0x1001011000001111).to_bytes(32,'big'))) == int(0x1001011011110000))

KEK = generate_common_KEK(0xABACABA, generate_public_key(0xABACABADABA, base_parameters_1), base_parameters_1)
assert(to_int(GOST2814789KeyUnWrap(GOST2814789KeyWrap(CEK, KEK), KEK)) == to_int(CEK))

test = GOST2814789KeyWrap(CEK, KEK)
test = (to_int(test) - 1).to_bytes(44, 'big')
assert(GOST2814789KeyUnWrap(test, KEK) == False)



print('OK.')
