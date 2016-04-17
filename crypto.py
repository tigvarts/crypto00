from module import *
import argparse
import sys

def to_int(msg):
  res = 0
  for i in range(len(msg)):
      res += (2**(8 * i)) * msg[-i-1]
  return res

parser = argparse.ArgumentParser()
group = parser.add_mutually_exclusive_group()
parser.add_argument('-o', '--output', help='output filename (default : "output")')
parser.add_argument('--secret_key', help='set name of file containing secret key (has default value, is used in KEK generation, public key generation, encrypt/decrypt in feedback mode(CEK), ECB encrypt/decrypt)')
#parser.add_argument('--parameters', help='set name of file containing parameters for DigitalSignatureParameters class (has default value, is used in KEK generation, public key generation)')
parser.add_argument('--IV', help='set name of file containing initializing vector for GOST 28147-89 Imit or encrypt/decrypt in feedback mode (has default value)')
parser.add_argument('--filename', help='set name of file containing message to encrypt/decrypt or hash')
parser.add_argument('--public_key', help='set name of file containing public key for generating KEK and complex encryption/decryption')
parser.add_argument('--CEK', help='set name of file containing CEK for key wrapping and complex encryption. Also used to save CEK key if --complex_decrypt is used')
parser.add_argument('--hex', action="store_true", help='specify if message in filename is in hex')
group.add_argument('--hash', action="store_true", help='GOST R 34.11-2012 hash')
group.add_argument('--generate_public_key', action="store_true", help='Generates public key based on secret key')
group.add_argument('--generate_KEK', action="store_true", help='Generates Key Encryption Key based on secret key and public key (specify secret key by using --secret_key and public key by using --public_key)')
group.add_argument('--encrypt_fm', action="store_true", help='Encrypts message according to GOST 28147-89 (feedback mode)')
group.add_argument('--decrypt_fm', action="store_true", help='Decrypts message according to GOST 28147-89 (feedback mode). Use --hex when using --filename')
group.add_argument('--complex_encrypt', action="store_true", help='Full cycle of encryption, generates KEK, encrypts message using CEK key, wraps the CEK by KEK. use --filename to specify message to encrypt, --public_key and --secret_key for generating KEK')
group.add_argument('--complex_decrypt', action="store_true", help='Full cycle of decryption, generates KEK, unwraps wrapped CEK and decrypts encrypted message. use --filename to specify encrypted message with wrapped CEK, --public_key and --secret_key for generating KEK')
group.add_argument('--ECB_encrypt', action="store_true", help='Encrypts message according to GOST 28147-89 (ECB mode)')
group.add_argument('--ECB_decrypt', action="store_true", help='Decrypts message according to GOST 28147-89 (ECB mode). Use --hex when using --filename')
group.add_argument('--imit', action="store_true", help='32-bit result of the GOST 28147-89 in MAC mode')
group.add_argument('--key_wrap', action="store_true", help='Encrypts GOST 28147-89 CEK with a GOST 28147-89 KEK (use --filename to specify file that contains CEK (also you should use --hex option) and --secret_key to specify file that contains KEK). Writes in file hex result')
group.add_argument('--key_unwrap', action="store_true", help='Decrypts GOST 28147-89 CEK with a GOST 28147-89 KEK (use --filename to specify file that contains encrypted CEK (dont forget to use --hex) and --secret_key to specify file that contains KEK)')

args = parser.parse_args()
output_file = open(args.output if args.output else 'output', "w")
secret_key = int(0x1001011011110000).to_bytes(32, 'big')
IV = False
msg = False

if args.secret_key:
  fp = open(args.secret_key)
  if not fp:
    print("Can't open file specified in --secret_key: using default value")
  else:
    secret_key = fp.readline()
    secret_key = int(secret_key, 16)
    fp.close()
    
if args.filename:
  fp = open(args.filename)
  if not fp:
    print("Can't open file specified in --filename")
    sys.exit(1)
  if args.hex:
    msg = int(fp.readline(), 16)
    msg = msg.to_bytes((msg.bit_length() // 8) + 1 , 'big')
  else:
    msg = fp.read().encode()
  fp.close()
if args.CEK:
  if not args.complex_decrypt:
    fp = open(args.CEK)
    if not fp:
      print("Can't open file specified in --CEK")
      sys.exit(1)
    CEK = int(fp.readline(), 16)
    fp.close()
  
if args.public_key:
  fp = open(args.public_key)
  if not fp:
    print("Can't open file specified in --public_key")
    sys.exit(1)
  public_key = (int(fp.readline()), int(fp.readline()))
  fp.close()
  
if args.IV:
  fp = open(args.IV)
  if fp:
    IV = int(fp.readline(), 16).to_bytes(8, 'big')
    fp.close()
  else:
    print("Can't open file specified in --IV: using default value")

if args.hash:
  hash = GOST34112012H256(msg)
  output_file.write(hex(to_int(hash)))

if args.generate_public_key:
  public_key = generate_public_key(secret_key, base_parameters_1)
  output_file.write(str(public_key[0])+'\n')
  output_file.write(str(public_key[1]))

if args.generate_KEK:
  KEK = generate_common_KEK(secret_key, public_key, base_parameters_1)
  output_file.write(hex(to_int(KEK)))

if args.encrypt_fm:
  cipher = cipher_feedback_mode_encode(msg, secret_key.to_bytes(32, 'big'), IV if IV else int(0).to_bytes(8, 'big'))
  output_file.write(hex(to_int(cipher)))
  
if args.decrypt_fm:
  decipher = cipher_feedback_mode_decode(msg, secret_key.to_bytes(32, 'big'), IV if IV else int(0).to_bytes(8, 'big'))
  output_file.write(decipher.decode())
  
if args.ECB_encrypt:
  if len(msg) % 8 != 0:
    print("Plain text must be 8n bytes long")
    sys.exit(1)
  cipher = GOST2814789ECB_encode(msg, secret_key.to_bytes(32, 'big'))
  output_file.write(hex(to_int(cipher))) 
  
if args.ECB_decrypt:
  if len(msg) % 8 != 0:
    print("Ciphered text must be 8n bytes long")
    sys.exit(1)
  decipher = GOST2814789ECB_decode(msg, secret_key.to_bytes(32, 'big'))
  output_file.write(decipher.decode())
  
if args.imit:
  if len(msg) % 8 != 0:
    print("Input text must be 8n bytes long")
    sys.exit(1)
  mac = GOST2814789IMIT(msg, secret_key.to_bytes(32, 'big'), IV if IV else int(0).to_bytes(8, 'big'))
  output_file.write(hex(to_int(mac)))
  
if args.key_wrap:
  wrapped = GOST2814789KeyWrap(CEK.to_bytes(32, 'big'), secret_key.to_bytes(32, 'big'))
  output_file.write(hex(to_int(wrapped)))
  
if args.key_unwrap:
  msg = to_int(msg).to_bytes(44, 'big') 
  CEK = GOST2814789KeyUnWrap(msg, secret_key.to_bytes(32, 'big'))
  if CEK:
    output_file.write(hex(to_int(CEK)))
  else:
    print("Cant unwrap, data is corrupted")

if args.complex_encrypt:
  KEK = generate_common_KEK(secret_key, public_key, base_parameters_1)
  print(to_int(KEK))
  wrapped = GOST2814789KeyWrap(CEK.to_bytes(32, 'big'), KEK)
  cipher = cipher_feedback_mode_encode(msg, CEK.to_bytes(32, 'big'), wrapped[0:8])
  output_file.write(hex(to_int(cipher)) + "\n")
  output_file.write(hex(to_int(wrapped)))
  
if args.complex_decrypt:
  fp = open(args.filename)
  if not fp:
    print("Can't open file specified in --filename")
    sys.exit(1)
  KEK = generate_common_KEK(secret_key, public_key, base_parameters_1)
  msg = int(fp.readline(), 16)
  print(to_int(KEK))
  msg = msg.to_bytes((msg.bit_length() // 8) + 1 , 'big')
  wrap = int(fp.readline(), 16).to_bytes(44, 'big')
  
  CEK = GOST2814789KeyUnWrap(wrap, KEK)
  if CEK:
    cek_file = open(args.CEK, "w")
    cek_file.write(hex(to_int(CEK)))
  else:
    print("Cant unwrap, data is corrupted")
    sys.exit(1)
  decipher = cipher_feedback_mode_decode(msg, CEK, wrap[0 : 8])
  output_file.write(decipher.decode())
  
output_file.close()
