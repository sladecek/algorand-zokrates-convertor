import binascii
import json
import sys
from py_ecc import bn128

class Zokrates2Algorand:
    """This script converts Groth16 ZK proofs from Zokrates to algorand.

    The script generates code snippets to be pasted into an algorand contract.
    """

    def read_pt1(self, pt1):
        """Converts group1 element from Zokrates JSON to py_ecc format.
        """
        pt = tuple([bn128.FQ(int(pt1[i], 16)) for i in range(2)])
        assert(bn128.is_on_curve(pt, bn128.b))
        return pt

    def read_fq2(self, fq2):
        """Converts FQ2 field element from Zokrates JSON to py_ecc format.
        """        
        return bn128.FQ2([int(fq2[i], 16) for i in range(2)])

    def read_pt2(self, pt):
        """Converts group2 element from Zokrates JSON to py_ecc format.
        """        
        pt = tuple([self.read_fq2(pt[i]) for i in range(2)])
        assert(bn128.is_on_curve(pt, bn128.b2))
        return pt    

    def print_pt1s(self, pts):
        """Converts group1 element from py_ecc format to algorand representation as byte array in hex.
        """        
        hx = ""
        for pt in pts:
            bs = [pt[i].n.to_bytes(32,"big") for i in range(2)]
            hx += binascii.hexlify(bs[0] + bs[1]).decode()
        return hx

    def print_pt2s(self, pts):
        """Converts group2 element from py_ecc format to algorand representation as byte array in hex.
        """ 
        hx = ""
        for pt in pts:
            bs = [pt[i].coeffs[j].n.to_bytes(32,"big") for i in range(2) for j in range(2)]
            hx += binascii.hexlify(bs[0] + bs[1] + bs[2] + bs[3]).decode()
        return hx

    def print_F(self, n):
        """Converts finite field element from py_ecc format to algorand representation as byte array in hex.
        """ 
        bs = n.to_bytes(16,"big")
        while len(bs) > 0 and bs[0] == 0:
            bs = bs[1::]
        hx = binascii.hexlify(bs).decode()
        return hx

    def read_zokrates_proof(self):
        """Read a proof in Zokrates format.
        """
        print("Reading proof")
        with open('proof.json') as f:  proof = json.load(f)
        self.a = self.read_pt1(proof['proof']['a'])
        self.b = self.read_pt2(proof['proof']['b'])
        self.c = self.read_pt1(proof['proof']['c'])
        self.inputs = [int(x, 16) for x in proof['inputs']]
        #print(a, b, c, inputs)

    def read_zokrates_verification_key(self):
        """Read a verification key in Zokrates format.
        """
        print("Reading verification key")
        with open('verification.key') as f:  key = json.load(f)
        self.alpha = self.read_pt1(key['alpha'])
        self.beta = self.read_pt2(key['beta'])
        self.gamma = self.read_pt2(key['gamma'])
        self.delta = self.read_pt2(key['delta'])
        self.gamma_abc = [self.read_pt1(x) for  x in key['gamma_abc']]

    def verify(self):
        """Verify a proof for debugging and testing. Also prints intermediate results.
        """
        print("Verification")
        vk_x = self.gamma_abc[0]
        for i in range(len(self.gamma_abc)-1):
            m = bn128.multiply(self.gamma_abc[i+1], self.inputs[i])
            vk_x = bn128.add(vk_x, m)
        
        print(f"  vkx_check = Bytes(\"base16\",\"0x{self.print_pt1s([vk_x])}\")")
        print(f"  g1_check = Bytes(\"base16\",\"0x{self.print_pt1s([self.a, vk_x, self.c, self.alpha])}\")")
        print(f"  g2_check = Bytes(\"base16\",\"0x{self.print_pt2s([self.b, bn128.neg(self.gamma), bn128.neg(self.delta), bn128.neg(self.beta)])}\")")

        r1 = bn128.pairing(self.b,self.a)
        r2 = bn128.pairing(bn128.neg(self.gamma), vk_x)
        r3 = bn128.pairing(bn128.neg(self.delta), self.c)
        r4 = bn128.pairing(bn128.neg(self.beta), self.alpha)
        r = r1 * r2 * r3 * r4
        ok = r == bn128.FQ12.one()
        print("OK" if ok else "NOT VERIFIED")

    def compile_proof(self):
        """Convert Zokrates proof to a code snippet used in smart contract call.
        """
        numbers = [ 
            self.print_pt1s([self.a]), 
            self.print_pt2s([self.b]), 
            self.print_pt1s([self.c]) 
        ] + [ self.print_F(i) for i in self.inputs ]
        for a in numbers:
            print(f"      args.append(binascii.unhexlify(\"{a}\"))")

    def compile_contract(self):
        """Converts Zokrates verification key to a code snippet used in the verification contract.
        """
        g2elems = self.print_pt2s([ bn128.neg(x) for x in [self.gamma, self.delta, self.beta]])
        print(f"  g2elems = Bytes(\"base16\",\"0x{g2elems}\")")
        g1elems = self.print_pt1s([self.alpha])
        print(f"  g1elems = Bytes(\"base16\",\"0x{g1elems}\")")
        for i in range(len(self.gamma_abc)):
            gammaabc = self.print_pt1s([self.gamma_abc[i]])
            print(f"  gammaabc_{i} = Bytes(\"base16\",\"0x{gammaabc}\")")
        
        print(f"  vkx = gammaabc_0")
        for i in range(len(self.gamma_abc)-1):
            print(f"  x = B256ScalarMul(gammaabc_{i+1}, Arg({i+3}))")
            print(f"  vkx = B256Add(vkx, x)")

        print(f"  g2 = Concat(Arg(1), g2elems)")
        print(f"  g1 = Concat(Arg(0), vkx, Arg(2), g1elems)")
        print(f"  return B256Pairing(g2, g1) == Int(1)")    

if __name__ == "__main__":
    cmd = sys.argv[1]
    if cmd == "verify":
        za = Zokrates2Algorand()
        za.read_zokrates_proof()
        za.read_zokrates_verification_key()
        za.verify()
    elif cmd == "compile_contract":
        za = Zokrates2Algorand()
        za.read_zokrates_verification_key()
        za.compile_contract()
    elif cmd == "compile_proof":
        za = Zokrates2Algorand()
        za.read_zokrates_proof()
        za.compile_proof()
    else:
        print("Usage: zokrates2algorand verify | compile_contract | compile_proof")
