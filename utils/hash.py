#=============================================================================#
# Based on: https://github.com/iagox86/nbtool/blob/master/samples/shellcode-win32/hash.py
# Article: https://medium.com/asecuritysite-when-bob-met-alice/ror13-and-its-linkage-to-api-calls-within-modules-c2191b35161d
#=============================================================================#
from sys import path
import os, time, sys
#=============================================================================#
def ror( dword, bits ):
  return ( dword >> bits | dword << ( 32 - bits ) ) & 0xFFFFFFFF
#=============================================================================#
def unicode( string, uppercase=True ):
  result = ""
  if uppercase:
    string = string.upper()
  for c in string:
    result += c + "\x00"
  return result
#=============================================================================#
def hash( function, bits=13, print_hash=True ):
  function_hash = 0
  for c in str( function ):
    function_hash  = ror( function_hash, bits )
    function_hash += ord( c )
  print("#define %s_HASH  0x%08X" % ( function.upper(), function_hash))
  return function_hash
#=============================================================================#
def main( argv=None ):
    
  if not argv:
    argv = sys.argv
  try:
    if len( argv ) != 2:
      print("Usage: hash.py <module / function name>")
    else:
      hash( argv[1] )
  except Exception as e:
    print("[-] ", e)
#=============================================================================#
if __name__ == "__main__":
  main(sys.argv)
#=============================================================================#