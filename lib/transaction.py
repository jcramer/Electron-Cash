#!/usr/bin/env python3
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2011 Thomas Voegtlin
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.



# Note: The deserialization code originally comes from ABE.

from .util import print_error, profiler
from .caches import ExpiringCache

from .bitcoin import *
from .address import (PublicKey, Address, Script, ScriptOutput, hash160,
                      UnknownAddress, OpCodes as opcodes)
from . import schnorr
from . import util
import struct
import warnings

#
# Workalike python implementation of Bitcoin's CDataStream class.
#
from .keystore import xpubkey_to_address, xpubkey_to_pubkey

NO_SIGNATURE = 'ff'


class SerializationError(Exception):
    """ Thrown when there's a problem deserializing or serializing """

class InputValueMissing(Exception):
    """ thrown when the value of an input is needed but not present """

class BCDataStream(object):
    def __init__(self):
        self.input = None
        self.read_cursor = 0

    def clear(self):
        self.input = None
        self.read_cursor = 0

    def write(self, _bytes):  # Initialize with string of _bytes
        if self.input is None:
            self.input = bytearray(_bytes)
        else:
            self.input += bytearray(_bytes)

    def read_string(self, encoding='ascii'):
        # Strings are encoded depending on length:
        # 0 to 252 :  1-byte-length followed by bytes (if any)
        # 253 to 65,535 : byte'253' 2-byte-length followed by bytes
        # 65,536 to 4,294,967,295 : byte '254' 4-byte-length followed by bytes
        # ... and the Bitcoin client is coded to understand:
        # greater than 4,294,967,295 : byte '255' 8-byte-length followed by bytes of string
        # ... but I don't think it actually handles any strings that big.
        if self.input is None:
            raise SerializationError("call write(bytes) before trying to deserialize")

        length = self.read_compact_size()

        return self.read_bytes(length).decode(encoding)

    def write_string(self, string, encoding='ascii'):
        string = to_bytes(string, encoding)
        # Length-encoded as with read-string
        self.write_compact_size(len(string))
        self.write(string)

    def read_bytes(self, length):
        try:
            result = self.input[self.read_cursor:self.read_cursor+length]
            self.read_cursor += length
            return result
        except IndexError:
            raise SerializationError("attempt to read past end of buffer")

        return ''

    def can_read_more(self) -> bool:
        if not self.input:
            return False
        return self.read_cursor < len(self.input)

    def read_boolean(self): return self.read_bytes(1)[0] != chr(0)
    def read_int16(self): return self._read_num('<h')
    def read_uint16(self): return self._read_num('<H')
    def read_int32(self): return self._read_num('<i')
    def read_uint32(self): return self._read_num('<I')
    def read_int64(self): return self._read_num('<q')
    def read_uint64(self): return self._read_num('<Q')

    def write_boolean(self, val): return self.write(chr(1) if val else chr(0))
    def write_int16(self, val): return self._write_num('<h', val)
    def write_uint16(self, val): return self._write_num('<H', val)
    def write_int32(self, val): return self._write_num('<i', val)
    def write_uint32(self, val): return self._write_num('<I', val)
    def write_int64(self, val): return self._write_num('<q', val)
    def write_uint64(self, val): return self._write_num('<Q', val)

    def read_compact_size(self):
        try:
            size = self.input[self.read_cursor]
            self.read_cursor += 1
            if size == 253:
                size = self._read_num('<H')
            elif size == 254:
                size = self._read_num('<I')
            elif size == 255:
                size = self._read_num('<Q')
            return size
        except IndexError:
            raise SerializationError("attempt to read past end of buffer")

    def write_compact_size(self, size):
        if size < 0:
            raise SerializationError("attempt to write size < 0")
        elif size < 253:
            self.write(bytes([size]))
        elif size < 2**16:
            self.write(b'\xfd')
            self._write_num('<H', size)
        elif size < 2**32:
            self.write(b'\xfe')
            self._write_num('<I', size)
        elif size < 2**64:
            self.write(b'\xff')
            self._write_num('<Q', size)

    def _read_num(self, format):
        try:
            (i,) = struct.unpack_from(format, self.input, self.read_cursor)
            self.read_cursor += struct.calcsize(format)
        except Exception as e:
            raise SerializationError(e)
        return i

    def _write_num(self, format, num):
        s = struct.pack(format, num)
        self.write(s)


# This function comes from bitcointools, bct-LICENSE.txt.
def long_hex(bytes):
    return bytes.encode('hex_codec')

# This function comes from bitcointools, bct-LICENSE.txt.
def short_hex(bytes):
    t = bytes.encode('hex_codec')
    if len(t) < 11:
        return t
    return t[0:4]+"..."+t[-4:]


def match_decoded(decoded, to_match):
    if len(decoded) != len(to_match):
        return False;
    for i in range(len(decoded)):
        if to_match[i] == opcodes.OP_PUSHDATA4 and decoded[i][0] <= opcodes.OP_PUSHDATA4 and decoded[i][0]>0:
            continue  # Opcodes below OP_PUSHDATA4 all just push data onto stack, and are equivalent.
        if to_match[i] != decoded[i][0]:
            return False
    return True


def parse_sig(x_sig):
    return [None if x == NO_SIGNATURE else x for x in x_sig]

def safe_parse_pubkey(x):
    try:
        return xpubkey_to_pubkey(x)
    except:
        return x

def parse_scriptSig(d, _bytes):
    try:
        decoded = Script.get_ops(_bytes)
    except Exception as e:
        # coinbase transactions raise an exception
        print_error("cannot find address in input script", bh2u(_bytes))
        return

    match = [ opcodes.OP_PUSHDATA4 ]
    if match_decoded(decoded, match):
        item = decoded[0][1]
        # payto_pubkey
        d['type'] = 'p2pk'
        d['signatures'] = [bh2u(item)]
        d['num_sig'] = 1
        d['x_pubkeys'] = ["(pubkey)"]
        d['pubkeys'] = ["(pubkey)"]
        return

    # non-generated TxIn transactions push a signature
    # (seventy-something bytes) and then their public key
    # (65 bytes) onto the stack:
    match = [ opcodes.OP_PUSHDATA4, opcodes.OP_PUSHDATA4 ]
    if match_decoded(decoded, match):
        sig = bh2u(decoded[0][1])
        x_pubkey = bh2u(decoded[1][1])
        try:
            signatures = parse_sig([sig])
            pubkey, address = xpubkey_to_address(x_pubkey)
        except:
            print_error("cannot find address in input script", bh2u(_bytes))
            return
        d['type'] = 'p2pkh'
        d['signatures'] = signatures
        d['x_pubkeys'] = [x_pubkey]
        d['num_sig'] = 1
        d['pubkeys'] = [pubkey]
        d['address'] = address
        return

    # p2sh transaction, m of n
    match = [ opcodes.OP_0 ] + [ opcodes.OP_PUSHDATA4 ] * (len(decoded) - 1)
    if not match_decoded(decoded, match):
        print_error("cannot find address in input script", bh2u(_bytes))
        return
    x_sig = [bh2u(x[1]) for x in decoded[1:-1]]
    m, n, x_pubkeys, pubkeys, redeemScript = parse_redeemScript(decoded[-1][1])
    # write result in d
    d['type'] = 'p2sh'
    d['num_sig'] = m
    d['signatures'] = parse_sig(x_sig)
    d['x_pubkeys'] = x_pubkeys
    d['pubkeys'] = pubkeys
    d['redeemScript'] = redeemScript
    d['address'] = Address.from_P2SH_hash(hash160(redeemScript))


def parse_redeemScript(s):
    dec2 = Script.get_ops(s)
    # the following throw exception when redeemscript has one or zero opcodes
    m = dec2[0][0] - opcodes.OP_1 + 1
    n = dec2[-2][0] - opcodes.OP_1 + 1
    op_m = opcodes.OP_1 + m - 1
    op_n = opcodes.OP_1 + n - 1
    match_multisig = [ op_m ] + [opcodes.OP_PUSHDATA4]*n + [ op_n, opcodes.OP_CHECKMULTISIG ]
    if not match_decoded(dec2, match_multisig):
        # causes exception in caller when mismatched
        print_error("cannot find address in input script", bh2u(s))
        return
    x_pubkeys = [bh2u(x[1]) for x in dec2[1:-2]]
    pubkeys = [safe_parse_pubkey(x) for x in x_pubkeys]
    redeemScript = Script.multisig_script(m, [bytes.fromhex(p)
                                              for p in pubkeys])
    return m, n, x_pubkeys, pubkeys, redeemScript

def get_address_from_output_script(_bytes):
    try:
        decoded = Script.get_ops(_bytes)

        # The Genesis Block, self-payments, and pay-by-IP-address payments look like:
        # 65 BYTES:... CHECKSIG
        match = [ opcodes.OP_PUSHDATA4, opcodes.OP_CHECKSIG ]
        if match_decoded(decoded, match):
            return TYPE_PUBKEY, PublicKey.from_pubkey(decoded[0][1])

        # Pay-by-Bitcoin-address TxOuts look like:
        # DUP HASH160 20 BYTES:... EQUALVERIFY CHECKSIG
        match = [ opcodes.OP_DUP, opcodes.OP_HASH160, opcodes.OP_PUSHDATA4, opcodes.OP_EQUALVERIFY, opcodes.OP_CHECKSIG ]
        if match_decoded(decoded, match):
            return TYPE_ADDRESS, Address.from_P2PKH_hash(decoded[2][1])

        # p2sh
        match = [ opcodes.OP_HASH160, opcodes.OP_PUSHDATA4, opcodes.OP_EQUAL ]
        if match_decoded(decoded, match):
            return TYPE_ADDRESS, Address.from_P2SH_hash(decoded[1][1])
    except Exception as e:
        print_error('{}: Failed to parse tx ouptut {}. Exception was: {}'.format(__name__, _bytes.hex(), repr(e)))
        pass

    return TYPE_SCRIPT, ScriptOutput(bytes(_bytes))


def parse_input(vds):
    d = {}
    prevout_hash = hash_encode(vds.read_bytes(32))
    prevout_n = vds.read_uint32()
    scriptSig = vds.read_bytes(vds.read_compact_size())
    sequence = vds.read_uint32()
    d['prevout_hash'] = prevout_hash
    d['prevout_n'] = prevout_n
    d['sequence'] = sequence
    d['address'] = UnknownAddress()
    if prevout_hash == '00'*32:
        d['type'] = 'coinbase'
        d['scriptSig'] = bh2u(scriptSig)
    else:
        d['x_pubkeys'] = []
        d['pubkeys'] = []
        d['signatures'] = {}
        d['address'] = None
        d['type'] = 'unknown'
        d['num_sig'] = 0
        d['scriptSig'] = bh2u(scriptSig)
        try:
            parse_scriptSig(d, scriptSig)
        except Exception as e:
            print_error('{}: Failed to parse tx input {}:{}, probably a p2sh (non multisig?). Exception was: {}'.format(__name__, prevout_hash, prevout_n, repr(e)))
            # that whole heuristic codepath is fragile; just ignore it when it dies.
            # failing tx examples:
            # 1c671eb25a20aaff28b2fa4254003c201155b54c73ac7cf9c309d835deed85ee
            # 08e1026eaf044127d7103415570afd564dfac3131d7a5e4b645f591cd349bb2c
            # override these once more just to make sure
            d['address'] = UnknownAddress()
            d['type'] = 'unknown'
        if not Transaction.is_txin_complete(d):
            d['value'] = vds.read_uint64()
    return d


def parse_output(vds, i):
    d = {}
    d['value'] = vds.read_int64()
    scriptPubKey = vds.read_bytes(vds.read_compact_size())
    d['type'], d['address'] = get_address_from_output_script(scriptPubKey)
    d['scriptPubKey'] = bh2u(scriptPubKey)
    d['prevout_n'] = i
    return d


def deserialize(raw):
    vds = BCDataStream()
    vds.write(bfh(raw))
    d = {}
    start = vds.read_cursor
    d['version'] = vds.read_int32()
    n_vin = vds.read_compact_size()
    assert n_vin != 0
    d['inputs'] = [parse_input(vds) for i in range(n_vin)]
    n_vout = vds.read_compact_size()
    assert n_vout != 0
    d['outputs'] = [parse_output(vds, i) for i in range(n_vout)]
    d['lockTime'] = vds.read_uint32()
    if vds.can_read_more():
        raise SerializationError('extra junk at the end')
    return d


# pay & redeem scripts



def multisig_script(public_keys, m):
    n = len(public_keys)
    assert n <= 15
    assert m <= n
    op_m = format(opcodes.OP_1 + m - 1, 'x')
    op_n = format(opcodes.OP_1 + n - 1, 'x')
    keylist = [op_push(len(k)//2) + k for k in public_keys]
    return op_m + ''.join(keylist) + op_n + 'ae'




class Transaction:

    SIGHASH_FORKID = 0x40  # do not use this; deprecated
    FORKID = 0x000000  # do not use this; deprecated

    def __str__(self):
        if self.raw is None:
            self.raw = self.serialize()
        return self.raw

    def __init__(self, raw, sign_schnorr=False):
        if raw is None:
            self.raw = None
        elif isinstance(raw, str):
            self.raw = raw.strip() if raw else None
        elif isinstance(raw, dict):
            self.raw = raw['hex']
        else:
            raise BaseException("cannot initialize transaction", raw)
        self._inputs = None
        self._outputs = None
        self.locktime = 0
        self.version = 1
        self._sign_schnorr = sign_schnorr

        # attribute used by HW wallets to tell the hw keystore about any outputs
        # in the tx that are to self (change), etc. See wallet.py add_hw_info
        # which writes to this dict and the various hw wallet plugins which
        # read this dict.
        self.output_info = dict()

        # Ephemeral meta-data used internally to keep track of interesting
        # things. This is currently written-to by coinchooser to tell UI code
        # about 'dust_to_fee', which is change that's too small to go to change
        # outputs (below dust threshold) and needed to go to the fee.
        #
        # It is also used to store the 'fetched_inputs' which are asynchronously
        # retrieved inputs (by retrieving prevout_hash tx's), see
        #`fetch_input_data`.
        #
        # Values in this dict are advisory only and may or may not always be
        # there!
        self.ephemeral = dict()

    def set_sign_schnorr(self, b):
        self._sign_schnorr = b

    def update(self, raw):
        self.raw = raw
        self._inputs = None
        self.deserialize()

    def inputs(self):
        if self._inputs is None:
            self.deserialize()
        return self._inputs

    def outputs(self):
        if self._outputs is None:
            self.deserialize()
        return self._outputs

    @classmethod
    def get_sorted_pubkeys(self, txin):
        # sort pubkeys and x_pubkeys, using the order of pubkeys
        # Note: this function is CRITICAL to get the correct order of pubkeys in
        # multisignatures; avoid changing.
        x_pubkeys = txin['x_pubkeys']
        pubkeys = txin.get('pubkeys')
        if pubkeys is None:
            pubkeys = [xpubkey_to_pubkey(x) for x in x_pubkeys]
            pubkeys, x_pubkeys = zip(*sorted(zip(pubkeys, x_pubkeys)))
            txin['pubkeys'] = pubkeys = list(pubkeys)
            txin['x_pubkeys'] = x_pubkeys = list(x_pubkeys)
        return pubkeys, x_pubkeys

    def update_signatures(self, signatures):
        """Add new signatures to a transaction
        `signatures` is expected to be a list of hex encoded sig strings with
        *no* sighash byte at the end (implicitly always 0x41 (SIGHASH_FORKID|SIGHASH_ALL);
        will be added by this function).

        signatures[i] is intended for self._inputs[i].

        The signature will be matched with the appropriate pubkey automatically
        in the case of multisignature wallets.

        This function is used by the Trezor, KeepKey, etc to update the
        transaction with signatures form the device.

        Note this function supports both Schnorr and ECDSA signatures, but as
        yet no hardware wallets are signing Schnorr.
        """
        if self.is_complete():
            return
        if not isinstance(signatures, (tuple, list)):
            raise Exception('API changed: update_signatures expects a list.')
        if len(self.inputs()) != len(signatures):
            raise Exception('expected {} signatures; got {}'.format(len(self.inputs()), len(signatures)))
        for i, txin in enumerate(self.inputs()):
            pubkeys, x_pubkeys = self.get_sorted_pubkeys(txin)
            sig = signatures[i]
            if not isinstance(sig, str):
                raise ValueError("sig was bytes, expected string")
            # sig_final is the signature with the sighashbyte at the end (0x41)
            sig_final = sig + '41'
            if sig_final in txin.get('signatures'):
                # skip if we already have this signature
                continue
            pre_hash = Hash(bfh(self.serialize_preimage(i)))
            sig_bytes = bfh(sig)
            added = False
            reason = []
            for j, pubkey in enumerate(pubkeys):
                # see which pubkey matches this sig (in non-multisig only 1 pubkey, in multisig may be multiple pubkeys)
                if self.verify_signature(bfh(pubkey), sig_bytes, pre_hash, reason):
                    print_error("adding sig", i, j, pubkey, sig_final)
                    self._inputs[i]['signatures'][j] = sig_final
                    added = True
            if not added:
                resn = ', '.join(reversed(reason)) if reason else ''
                print_error("failed to add signature {} for any pubkey for reason(s): '{}' ; pubkey(s) / sig / pre_hash = ".format(i, resn),
                            pubkeys, '/', sig, '/', bh2u(pre_hash))
        # redo raw
        self.raw = self.serialize()

    def is_schnorr_signed(self, input_idx):
        ''' Return True IFF any of the signatures for a particular input
        are Schnorr signatures (Schnorr signatures are always 64 bytes + 1) '''
        if (isinstance(self._inputs, (list, tuple))
                and input_idx < len(self._inputs)
                and self._inputs[input_idx]):
            # Schnorr sigs are always 64 bytes. However the sig has a hash byte
            # at the end, so that's 65. Plus we are hex encoded, so 65*2=130
            return any(isinstance(sig, (str, bytes)) and len(sig) == 130
                       for sig in self._inputs[input_idx].get('signatures', []))
        return False

    def deserialize(self):
        if self.raw is None:
            return
        if self._inputs is not None:
            return
        d = deserialize(self.raw)
        self._inputs = d['inputs']
        self._outputs = [(x['type'], x['address'], x['value']) for x in d['outputs']]
        assert all(isinstance(output[1], (PublicKey, Address, ScriptOutput))
                   for output in self._outputs)
        self.locktime = d['lockTime']
        self.version = d['version']
        return d

    @classmethod
    def from_io(klass, inputs, outputs, locktime=0, sign_schnorr=False):
        assert all(isinstance(output[1], (PublicKey, Address, ScriptOutput))
                   for output in outputs)
        self = klass(None)
        self._inputs = inputs
        self._outputs = outputs.copy()
        self.locktime = locktime
        self.set_sign_schnorr(sign_schnorr)
        return self

    @classmethod
    def pay_script(self, output):
        return output.to_script().hex()

    @classmethod
    def estimate_pubkey_size_from_x_pubkey(cls, x_pubkey):
        try:
            if x_pubkey[0:2] in ['02', '03']:  # compressed pubkey
                return 0x21
            elif x_pubkey[0:2] == '04':  # uncompressed pubkey
                return 0x41
            elif x_pubkey[0:2] == 'ff':  # bip32 extended pubkey
                return 0x21
            elif x_pubkey[0:2] == 'fe':  # old electrum extended pubkey
                return 0x41
        except Exception as e:
            pass
        return 0x21  # just guess it is compressed

    @classmethod
    def estimate_pubkey_size_for_txin(cls, txin):
        pubkeys = txin.get('pubkeys', [])
        x_pubkeys = txin.get('x_pubkeys', [])
        if pubkeys and len(pubkeys) > 0:
            return cls.estimate_pubkey_size_from_x_pubkey(pubkeys[0])
        elif x_pubkeys and len(x_pubkeys) > 0:
            return cls.estimate_pubkey_size_from_x_pubkey(x_pubkeys[0])
        else:
            return 0x21  # just guess it is compressed

    @classmethod
    def get_siglist(self, txin, estimate_size=False, sign_schnorr=False):
        # if we have enough signatures, we use the actual pubkeys
        # otherwise, use extended pubkeys (with bip32 derivation)
        num_sig = txin.get('num_sig', 1)
        if estimate_size:
            pubkey_size = self.estimate_pubkey_size_for_txin(txin)
            pk_list = ["00" * pubkey_size] * len(txin.get('x_pubkeys', [None]))
            # we assume that signature will be 0x48 bytes long if ECDSA, 0x41 if Schnorr
            if sign_schnorr:
                siglen = 0x41
            else:
                siglen = 0x48
            sig_list = [ "00" * siglen ] * num_sig
        else:
            pubkeys, x_pubkeys = self.get_sorted_pubkeys(txin)
            x_signatures = txin['signatures']
            signatures = list(filter(None, x_signatures))
            is_complete = len(signatures) == num_sig
            if is_complete:
                pk_list = pubkeys
                sig_list = signatures
            else:
                pk_list = x_pubkeys
                sig_list = [sig if sig else NO_SIGNATURE for sig in x_signatures]
        return pk_list, sig_list

    @classmethod
    def input_script(self, txin, estimate_size=False, sign_schnorr=False):
        _type = txin['type']
        if _type == 'coinbase':
            return txin['scriptSig']
        pubkeys, sig_list = self.get_siglist(txin, estimate_size, sign_schnorr=sign_schnorr)
        script = ''.join(push_script(x) for x in sig_list)
        if _type == 'p2pk':
            pass
        elif _type == 'p2sh':
            # put op_0 before script
            script = '00' + script
            redeem_script = multisig_script(pubkeys, txin['num_sig'])
            script += push_script(redeem_script)
        elif _type == 'p2pkh':
            script += push_script(pubkeys[0])
        elif _type == 'unknown':
            return txin['scriptSig']
        return script

    @classmethod
    def is_txin_complete(self, txin):
        num_sig = txin.get('num_sig', 1)
        x_signatures = txin['signatures']
        signatures = list(filter(None, x_signatures))
        return len(signatures) == num_sig

    @classmethod
    def get_preimage_script(self, txin):
        _type = txin['type']
        if _type == 'p2pkh':
            return txin['address'].to_script().hex()
        elif _type == 'p2sh':
            pubkeys, x_pubkeys = self.get_sorted_pubkeys(txin)
            return multisig_script(pubkeys, txin['num_sig'])
        elif _type == 'p2pk':
            pubkey = txin['pubkeys'][0]
            return public_key_to_p2pk_script(pubkey)
        elif _type == 'unknown':
            # this approach enables most P2SH smart contracts (but take care if using OP_CODESEPARATOR)
            return txin['scriptCode']
        else:
            raise RuntimeError('Unknown txin type', _type)

    @classmethod
    def serialize_outpoint(self, txin):
        return bh2u(bfh(txin['prevout_hash'])[::-1]) + int_to_hex(txin['prevout_n'], 4)

    @classmethod
    def serialize_input(self, txin, script, estimate_size=False):
        # Prev hash and index
        s = self.serialize_outpoint(txin)
        # Script length, script, sequence
        s += var_int(len(script)//2)
        s += script
        s += int_to_hex(txin.get('sequence', 0xffffffff - 1), 4)
        # offline signing needs to know the input value
        if ('value' in txin   # Legacy txs
            and not (estimate_size or self.is_txin_complete(txin))):
            s += int_to_hex(txin['value'], 8)
        return s

    def BIP_LI01_sort(self):
        # See https://github.com/kristovatlas/rfc/blob/master/bips/bip-li01.mediawiki
        self._inputs.sort(key = lambda i: (i['prevout_hash'], i['prevout_n']))
        self._outputs.sort(key = lambda o: (o[2], self.pay_script(o[1])))

    def serialize_output(self, output):
        output_type, addr, amount = output
        s = int_to_hex(amount, 8)
        script = self.pay_script(addr)
        s += var_int(len(script)//2)
        s += script
        return s

    @classmethod
    def nHashType(cls):
        '''Hash type in hex.'''
        warnings.warn("warning: deprecated tx.nHashType()", FutureWarning, stacklevel=2)
        return 0x01 | (cls.SIGHASH_FORKID + (cls.FORKID << 8))

    def serialize_preimage(self, i, nHashType=0x00000041):
        if (nHashType & 0xff) != 0x41:
            raise ValueError("other hashtypes not supported; submit a PR to fix this!")

        nVersion = int_to_hex(self.version, 4)
        nHashType = int_to_hex(nHashType, 4)
        nLocktime = int_to_hex(self.locktime, 4)
        inputs = self.inputs()
        outputs = self.outputs()
        txin = inputs[i]

        hashPrevouts = bh2u(Hash(bfh(''.join(self.serialize_outpoint(txin) for txin in inputs))))
        hashSequence = bh2u(Hash(bfh(''.join(int_to_hex(txin.get('sequence', 0xffffffff - 1), 4) for txin in inputs))))
        hashOutputs = bh2u(Hash(bfh(''.join(self.serialize_output(o) for o in outputs))))
        outpoint = self.serialize_outpoint(txin)
        preimage_script = self.get_preimage_script(txin)
        scriptCode = var_int(len(preimage_script) // 2) + preimage_script
        try:
            amount = int_to_hex(txin['value'], 8)
        except KeyError:
            raise InputValueMissing
        nSequence = int_to_hex(txin.get('sequence', 0xffffffff - 1), 4)
        preimage = nVersion + hashPrevouts + hashSequence + outpoint + scriptCode + amount + nSequence + hashOutputs + nLocktime + nHashType
        return preimage

    def serialize(self, estimate_size=False):
        nVersion = int_to_hex(self.version, 4)
        nLocktime = int_to_hex(self.locktime, 4)
        inputs = self.inputs()
        outputs = self.outputs()
        txins = var_int(len(inputs)) + ''.join(self.serialize_input(txin, self.input_script(txin, estimate_size, self._sign_schnorr), estimate_size) for txin in inputs)
        txouts = var_int(len(outputs)) + ''.join(self.serialize_output(o) for o in outputs)
        return nVersion + txins + txouts + nLocktime

    def hash(self):
        warnings.warn("warning: deprecated tx.hash()", FutureWarning, stacklevel=2)
        return self.txid()

    def txid(self):
        if not self.is_complete():
            return None
        ser = self.serialize()
        return self._txid(ser)

    @staticmethod
    def _txid(raw_hex : str) -> str:
        return bh2u(Hash(bfh(raw_hex))[::-1])

    def add_inputs(self, inputs):
        self._inputs.extend(inputs)
        self.raw = None

    def add_outputs(self, outputs):
        assert all(isinstance(output[1], (PublicKey, Address, ScriptOutput))
                   for output in outputs)
        self._outputs.extend(outputs)
        self.raw = None

    def input_value(self):
        return sum(x['value'] for x in (self.fetched_inputs() or self.inputs()))

    def output_value(self):
        return sum(val for tp, addr, val in self.outputs())

    def get_fee(self):
        return self.input_value() - self.output_value()

    @profiler
    def estimated_size(self):
        '''Return an estimated tx size in bytes.'''
        return (len(self.serialize(True)) // 2 if not self.is_complete() or self.raw is None
                else len(self.raw) // 2)  # ASCII hex string

    @classmethod
    def estimated_input_size(self, txin, sign_schnorr=False):
        '''Return an estimated of serialized input size in bytes.'''
        script = self.input_script(txin, True, sign_schnorr=sign_schnorr)
        return len(self.serialize_input(txin, script, True)) // 2  # ASCII hex string

    def signature_count(self):
        r = 0
        s = 0
        for txin in self.inputs():
            if txin['type'] == 'coinbase':
                continue
            signatures = list(filter(None, txin.get('signatures',[])))
            s += len(signatures)
            r += txin.get('num_sig',-1)
        return s, r

    def is_complete(self):
        s, r = self.signature_count()
        return r == s

    @staticmethod
    def verify_signature(pubkey, sig, msghash, reason=None):
        ''' Given a pubkey (bytes), signature (bytes -- without sighash byte),
        and a sha256d message digest, returns True iff the signature is good
        for the given public key, False otherwise.  Does not raise normally
        unless given bad or garbage arguments.

        Optional arg 'reason' should be a list which will have a string pushed
        at the front (failure reason) on False return. '''
        if (any(not arg or not isinstance(arg, bytes) for arg in (pubkey, sig, msghash))
                or len(msghash) != 32):
            raise ValueError('bad arguments to verify_signature')
        if len(sig) == 64:
            # Schnorr signatures are always exactly 64 bytes
            return schnorr.verify(pubkey, sig, msghash)
        else:
            from ecdsa import BadSignatureError, BadDigestError
            from ecdsa.der import UnexpectedDER
            # ECDSA signature
            try:
                pubkey_point = ser_to_point(pubkey)
                vk = MyVerifyingKey.from_public_point(pubkey_point, curve=SECP256k1)
                if vk.verify_digest(sig, msghash, sigdecode = ecdsa.util.sigdecode_der):
                   return True
            except (AssertionError, ValueError, TypeError,
                    BadSignatureError, BadDigestError, UnexpectedDER) as e:
                # ser_to_point will fail if pubkey is off-curve, infinity, or garbage.
                # verify_digest may also raise BadDigestError and BadSignatureError
                if isinstance(reason, list):
                    reason.insert(0, repr(e))
            except BaseException as e:
                print_error("[Transaction.verify_signature] unexpected exception", repr(e))
                if isinstance(reason, list):
                    reason.insert(0, repr(e))
            return False


    @staticmethod
    def _ecdsa_sign(sec, pre_hash):
        pkey = regenerate_key(sec)
        secexp = pkey.secret
        private_key = MySigningKey.from_secret_exponent(secexp, curve = SECP256k1)
        public_key = private_key.get_verifying_key()
        sig = private_key.sign_digest_deterministic(pre_hash, hashfunc=hashlib.sha256, sigencode = ecdsa.util.sigencode_der)
        assert public_key.verify_digest(sig, pre_hash, sigdecode = ecdsa.util.sigdecode_der)
        return sig

    @staticmethod
    def _schnorr_sign(pubkey, sec, pre_hash):
        pubkey = bytes.fromhex(pubkey)
        sig = schnorr.sign(sec, pre_hash)
        assert schnorr.verify(pubkey, sig, pre_hash)  # verify what we just signed
        return sig


    def sign(self, keypairs):
        for i, txin in enumerate(self.inputs()):
            num = txin['num_sig']
            pubkeys, x_pubkeys = self.get_sorted_pubkeys(txin)
            for j, x_pubkey in enumerate(x_pubkeys):
                signatures = list(filter(None, txin['signatures']))
                if len(signatures) == num:
                    # txin is complete
                    break
                if x_pubkey in keypairs.keys():
                    print_error("adding signature for", x_pubkey, "use schnorr?", self._sign_schnorr)
                    sec, compressed = keypairs.get(x_pubkey)
                    pubkey = public_key_from_private_key(sec, compressed)
                    # add signature
                    nHashType = 0x00000041 # hardcoded, perhaps should be taken from unsigned input dict
                    pre_hash = Hash(bfh(self.serialize_preimage(i, nHashType)))
                    if self._sign_schnorr:
                        sig = self._schnorr_sign(pubkey, sec, pre_hash)
                    else:
                        sig = self._ecdsa_sign(sec, pre_hash)
                    txin['signatures'][j] = bh2u(sig + bytes((nHashType & 0xff,)))
                    txin['pubkeys'][j] = pubkey # needed for fd keys
                    self._inputs[i] = txin
        print_error("is_complete", self.is_complete())
        self.raw = self.serialize()

    def get_outputs(self):
        """convert pubkeys to addresses"""
        o = []
        for type, addr, v in self.outputs():
            o.append((addr,v))      # consider using yield (addr, v)
        return o

    def get_output_addresses(self):
        return [addr for addr, val in self.get_outputs()]


    def has_address(self, addr):
        return (addr in self.get_output_addresses()) or (addr in (tx.get("address") for tx in self.inputs()))

    def is_final(self):
        return not any([x.get('sequence', 0xffffffff - 1) < 0xffffffff - 1
                        for x in self.inputs()])


    def as_dict(self):
        if self.raw is None:
            self.raw = self.serialize()
        self.deserialize()
        out = {
            'hex': self.raw,
            'complete': self.is_complete(),
            'final': self.is_final(),
        }
        return out

    # This cache stores foreign (non-wallet) tx's we fetched from the network
    # for the purposes of the "fetch_input_data" mechanism. Its max size has
    # been thoughtfully calibrated to provide a decent tradeoff between
    # memory consumption and UX.
    #
    # In even aggressive/pathological cases this cache won't ever exceed
    # 100MB even when full. [see ExpiringCache.size_bytes() to test it].
    # This is acceptable considering this is Python + Qt and it eats memory
    # anyway.. and also this is 2019 ;). Note that all tx's in this cache
    # are in the non-deserialized state (hex encoded bytes only) as a memory
    # savings optimization.  Please maintain that invariant if you modify this
    # code, otherwise the cache may grow to 10x memory consumption if you
    # put deserialized tx's in here.
    _fetched_tx_cache = ExpiringCache(maxlen=1000, name="TransactionFetchCache")

    def fetch_input_data(self, wallet, done_callback=None, done_args=tuple(),
                         prog_callback=None, *, force=False, use_network=True):
        '''
        Fetch all input data and put it in the 'ephemeral' dictionary, under
        'fetched_inputs'. This call potentially initiates fetching of
        prevout_hash transactions from the network for all inputs to this tx.

        The fetched data is basically used for the Transaction dialog to be able
        to display fee, actual address, and amount (value) for tx inputs.

        `wallet` should ideally have a network object, but this function still
        will work and is still useful if it does not.

        `done_callback` is called with `done_args` (only if True was returned),
        upon completion. Note that done_callback won't be called if this function
        returns False. Also note that done_callback runs in a non-main thread
        context and as such, if you want to do GUI work from within it, use
        the appropriate Qt signal/slot mechanism to dispatch work to the GUI.

        `prog_callback`, if specified, is called periodically to indicate
        progress after inputs are retrieved, and it is passed a single arg,
        "percent" (eg: 5.1, 10.3, 26.3, 76.1, etc) to indicate percent progress.

        Note 1: Results (fetched transactions) are cached, so subsequent
        calls to this function for the same transaction are cheap.

        Note 2: Multiple, rapid calls to this function will cause the previous
        asynchronous fetch operation (if active) to be canceled and only the
        latest call will result in the invocation of the done_callback if/when
        it completes.
        '''
        if not self._inputs:
            return False
        if force:
            # forced-run -- start with empty list
            inps = []
        else:
            # may be a new list or list that was already in dict
            inps = self.fetched_inputs(require_complete = True)
        if len(self._inputs) == len(inps):
            # we already have results, don't do anything.
            return False
        eph = self.ephemeral
        eph['fetched_inputs'] = inps = inps.copy()  # paranoia: in case another thread is running on this list
        # Lazy imports to keep this functionality very self-contained
        # These modules are always available so no need to globally import them.
        import threading
        import queue
        import time
        from copy import deepcopy
        from collections import defaultdict
        t0 = time.time()
        t = None
        cls = __class__
        def doIt():
            '''
            This function is seemingly complex, but it's really conceptually
            simple:
            1. Fetch all prevouts either from cache (wallet or global tx_cache)
            2. Or, if they aren't in either cache, then we will asynchronously
               queue the raw tx gets to the network in parallel, across *all*
               our connected servers. This is very fast, and spreads the load
               around.

            Tested with a huge tx of 600+ inputs all coming from different
            prevout_hashes on mainnet, and it's super fast:
            cd8fcc8ad75267ff9ad314e770a66a9e871be7882b7c05a7e5271c46bfca98bc '''
            last_prog = -9999.0
            need_dl_txids = defaultdict(list)  # the dict of txids we will need to download (wasn't in cache)
            def prog(i, prog_total=100):
                ''' notify interested code about progress '''
                nonlocal last_prog
                if prog_callback:
                    prog = ((i+1)*100.0)/prog_total
                    if prog - last_prog > 5.0:
                        prog_callback(prog)
                        last_prog = prog
            while eph.get('_fetch') == t and len(inps) < len(self._inputs):
                i = len(inps)
                inp = deepcopy(self._inputs[i])
                typ, prevout_hash, n, addr, value = inp.get('type'), inp.get('prevout_hash'), inp.get('prevout_n'), inp.get('address'), inp.get('value')
                if not prevout_hash or n is None:
                    raise RuntimeError('Missing prevout_hash and/or prevout_n')
                if typ != 'coinbase' and (not isinstance(addr, Address) or value is None):
                    tx = cls.tx_cache_get(prevout_hash) or wallet.transactions.get(prevout_hash)
                    if tx:
                        # Tx was in cache or wallet.transactions, proceed
                        # note that the tx here should be in the "not
                        # deserialized" state
                        if tx.raw:
                            # Note we deserialize a *copy* of the tx so as to
                            # save memory.  We do not want to deserialize the
                            # cached tx because if we do so, the cache will
                            # contain a deserialized tx which will take up
                            # several times the memory when deserialized due to
                            # Python's memory use being less efficient than the
                            # binary-only raw bytes.  So if you modify this code
                            # do bear that in mind.
                            tx = Transaction(tx.raw)
                            try:
                                tx.deserialize()
                                # The below txid check is commented-out as
                                # we trust wallet tx's and the network
                                # tx's that fail this check are never
                                # put in cache anyway.
                                #txid = tx._txid(tx.raw)
                                #if txid != prevout_hash: # sanity check
                                #    print_error("fetch_input_data: cached prevout_hash {} != tx.txid() {}, ignoring.".format(prevout_hash, txid))
                            except Exception as e:
                                print_error("fetch_input_data: WARNING failed to deserialize {}: {}".format(prevout_hash, repr(e)))
                                tx = None
                        else:
                            tx = None
                            print_error("fetch_input_data: WARNING cached tx lacked any 'raw' bytes for {}".format(prevout_hash))
                    # now, examine the deserialized tx, if it's still good
                    if tx:
                        if n < len(tx.outputs()):
                            outp = tx.outputs()[n]
                            addr, value = outp[1], outp[2]
                            inp['value'] = value
                            inp['address'] = addr
                            print_error("fetch_input_data: fetched cached", i, addr, value)
                        else:
                            print_error("fetch_input_data: ** FIXME ** should never happen -- n={} >= len(tx.outputs())={} for prevout {}".format(n, len(tx.outputs()), prevout_hash))
                    else:
                        # tx was not in cache or wallet.transactions, mark
                        # it for download below (this branch can also execute
                        # in the unlikely case where there was an error above)
                        need_dl_txids[prevout_hash].append((i, n))  # remember the input# as well as the prevout_n

                inps.append(inp) # append either cached result or as-yet-incomplete copy of _inputs[i]
            # Now, download the tx's we didn't find above if network is available
            # and caller said it's ok to go out ot network.. otherwise just return
            # what we have
            if use_network and eph.get('_fetch') == t and wallet.network and need_dl_txids:
                try:  # the whole point of this try block is the `finally` way below...
                    prog(-1)  # tell interested code that progress is now 0%
                    # Next, queue the transaction.get requests, spreading them
                    # out randomly over the connected interfaces
                    q = queue.Queue()
                    q_ct = 0
                    bad_txids = set()
                    def put_in_queue_and_cache(r):
                        ''' we cache the results directly in the network callback
                        as even if the user cancels the operation, we would like
                        to save the returned tx in our cache, since we did the
                        work to retrieve it anyway. '''
                        q.put(r)  # put the result in the queue no matter what it is
                        txid = ''
                        try:
                            # Below will raise if response was 'error' or
                            # otherwise invalid. Note: for performance reasons
                            # we don't validate the tx here or deserialize it as
                            # this function runs in the network thread and we
                            # don't want to eat up that thread's CPU time
                            # needlessly. Also note the cache doesn't store
                            # deserializd tx's so as to save memory. We
                            # always deserialize a copy when reading the cache.
                            tx = Transaction(r['result'])
                            txid = r['params'][0]
                            assert txid == cls._txid(tx.raw), "txid-is-sane-check"  # protection against phony responses
                            cls.tx_cache_put(tx=tx, txid=txid)  # save tx to cache here
                        except Exception as e:
                            # response was not valid, ignore (don't cache)
                            if txid:  # txid may be '' if KeyError from r['result'] above
                                bad_txids.add(txid)
                            print_error("fetch_input_data: put_in_queue_and_cache fail for txid:", txid, repr(e))
                    for txid, l in need_dl_txids.items():
                        wallet.network.queue_request('blockchain.transaction.get', [txid],
                                                     interface='random',
                                                     callback=put_in_queue_and_cache)
                        q_ct += 1
                    class ErrorResp(Exception):
                        pass
                    for i in range(q_ct):
                        # now, read the q back, with a 10 second timeout, and
                        # populate the inputs
                        try:
                            r = q.get(timeout=10)
                            if eph.get('_fetch') != t:
                                # early abort from func, canceled
                                break
                            if r.get('error'):
                                msg = r.get('error')
                                if isinstance(msg, dict):
                                    msg = msg.get('message') or 'unknown error'
                                raise ErrorResp(msg)
                            rawhex = r['result']
                            txid = r['params'][0]
                            assert txid not in bad_txids, "txid marked bad"  # skip if was marked bad by our callback code
                            tx = Transaction(rawhex); tx.deserialize()
                            for item in need_dl_txids[txid]:
                                ii, n = item
                                assert n < len(tx.outputs())
                                outp = tx.outputs()[n]
                                addr, value = outp[1], outp[2]
                                inps[ii]['value'] = value
                                inps[ii]['address'] = addr
                                print_error("fetch_input_data: fetched from network", ii, addr, value)
                            prog(i, q_ct)  # tell interested code of progress
                        except queue.Empty:
                            print_error("fetch_input_data: timed out after 10.0s fetching from network, giving up.")
                            break
                        except Exception as e:
                            print_error("fetch_input_data:", repr(e))
                finally:
                    # force-cancel any extant requests -- this is especially
                    # crucial on error/timeout/failure.
                    wallet.network.cancel_requests(put_in_queue_and_cache)
            if len(inps) == len(self._inputs) and eph.get('_fetch') == t:  # sanity check
                eph.pop('_fetch', None)  # potential race condition here, popping wrong t -- but in practice w/ CPython threading it won't matter
                print_error("fetch_input_data: elapsed {} sec".format(time.time()-t0))
                if done_callback:
                    done_callback(*done_args)
        # /doIt
        t = threading.Thread(target=doIt, daemon=True)
        eph['_fetch'] = t
        t.start()
        return True

    def fetched_inputs(self, *, require_complete=False):
        ''' Returns the complete list of asynchronously fetched inputs for
        this tx, if they exist. If the list is not yet fully retrieved, and
        require_complete == False, returns what it has so far
        (the returned list will always be exactly equal to len(self._inputs),
        with not-yet downloaded inputs coming from self._inputs and not
        necessarily containing a good 'address' or 'value').

        If the download failed completely or was never started, will return the
        empty list [].

        Note that some inputs may still lack key: 'value' if there was a network
        error in retrieving them or if the download is still in progress.'''
        if self._inputs:
            ret = self.ephemeral.get('fetched_inputs') or []
            diff = len(self._inputs) - len(ret)
            if diff > 0 and self.ephemeral.get('_fetch') and not require_complete:
                # in progress.. so return what we have so far
                return ret + self._inputs[len(ret):]
            elif diff == 0 and (not require_complete or not self.ephemeral.get('_fetch')):
                # finished *or* in-progress and require_complete==False
                return ret
        return []

    def fetch_cancel(self) -> bool:
        ''' Cancels the currently-active running fetch operation, if any '''
        return bool(self.ephemeral.pop('_fetch', None))

    @classmethod
    def tx_cache_get(cls, txid : str) -> object:
        ''' Attempts to retrieve txid from the tx cache that this class
        keeps in-memory.  Returns None on failure. The returned tx is
        not deserialized, and is a copy of the one in the cache. '''
        tx = cls._fetched_tx_cache.get(txid)
        if tx is not None and tx.raw:
            # make sure to return a copy of the transaction from the cache
            # so that if caller does .deserialize(), *his* instance will
            # use up 10x memory consumption, and not the cached instance which
            # should just be an undeserialized raw tx.
            return Transaction(tx.raw)
        return None

    @classmethod
    def tx_cache_put(cls, tx : object, txid : str = None):
        ''' Puts a non-deserialized copy of tx into the tx_cache. '''
        if not tx or not tx.raw:
            raise ValueError('Please pass a tx which has a valid .raw attribute!')
        txid = txid or cls._txid(tx.raw)  # optionally, caller can pass-in txid to save CPU time for hashing
        cls._fetched_tx_cache.put(txid, Transaction(tx.raw))


def tx_from_str(txt):
    "json or raw hexadecimal"
    import json
    txt = txt.strip()
    if not txt:
        raise ValueError("empty string")
    try:
        bfh(txt)
        is_hex = True
    except:
        is_hex = False
    if is_hex:
        return txt
    tx_dict = json.loads(str(txt))
    assert "hex" in tx_dict.keys()
    return tx_dict["hex"]
