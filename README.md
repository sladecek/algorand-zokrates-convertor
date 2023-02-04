# Validating Zero-Knowledge Proofs in the Algorand Smart Contract.

This project implements a convertor which enables to verify Zero-Knowledge proofs generated by
the [ZoKrates framework](https://zokrates.github.io/introduction.html]) into 
[PyTeal](https://pyteal.readthedocs.io/en/stable/) smart contracts. As an example a contract
that pays for knowledge of a magic square is included.

A Zero-Knowledge proof is a method for one party (the prover) to prove to
another party (the verifier) that they know a certain piece of information,
without revealing any additional information about that piece of information.
This means that the verifier can be sure that the prover knows the information,
but they don't learn anything else about it. It can be used to prove that a
person is over a certain age without revealing their exact birthdate or proving
that a person has a certain degree without revealing their grades.

*ZoKrates* is an open-source toolbox for zk-SNARKs (zero-knowledge succinct
non-interactive arguments of knowledge) on the Ethereum blockchain. It allows
developers to create and execute programs written in a high-level programming
language (similar to Python) and then convert them into zk-SNARKs, which can be
verified on the Ethereum blockchain. ZoKrates is written in Rust, and it can be
run on Linux, Windows, and MacOS platforms. It is useful for creating
decentralized applications (dApps) that require privacy and security, such as
digital identity verification, private voting systems, and private financial
transactions.

Unfortunatelly, there is no native support for Algorand in ZoKrates, only Solidity contracts are generated. 

This software can take a prover and a verifier generated in ZoKrates and
convert it into two code snippets - one for an *PyTeal* contract that verifies
the proof and one for the caller to encode the proof into transaction arguments. 

The demo is based on the *ZK-verifier demo for Algorand*.


# Usage


## Development Setup

This repo requires Python 3.6 or higher. We recommend you use a Python virtual environment to install
the required dependencies.

Set up venv (one time):
 * `python3 -m venv venv`

Active venv:
 * `. venv/bin/activate` (if your shell is bash/zsh)
 * `. venv/bin/activate.fish` (if your shell is fish)

Install dependencies:
* `pip install -r requirements.txt`

Sandbox:
* First, start an instance of [sandbox](https://github.com/algorand/sandbox) (requires Docker): `./sandbox up nightly`
* When finished, the sandbox can be stopped with `./sandbox down`

### Creating a ZK Verifier in ZoKrates

* [Install](https://zokrates.github.io/gettingstarted.html) ZoKrates. A docker image is available.
* Create a ZoKrates program. For the purpose of this project, there is a sample ZoKrates program
  available in the [zokrates/magic_square.zok](zokrates/magic_square.zok) file. The program validates that the prover knows
  a solution to a [magic square](https://en.wikipedia.org/wiki/Magic_square) puzzle. The values of
  the square comprise the witness of the  ZK problem. The sum of the rows and columns is the public
  input of the ZK circuit.

```
/*
    +-----+------+-----+
    | a0  |  a1  |  a2 |
    +-----+------+-----+
    | a3  |  a4  |  a5 |
    +-----+------+-----+
    | a6  |  a7  |  a8 |
    +-----+------+-----+

    This is a Magic Square. This means that the numbers add up to the same total in every direction.
    Every row, column and diagonal should add up to {sum}.
*/

def main(private field[9] a, field sum) {
    // horizontal
    assert(a[0] + a[1] + a[2] == sum);
    assert(a[3] + a[4] + a[5] == sum);
    assert(a[6] + a[7] + a[8] == sum);

    // vertical
    assert(a[0] + a[3] + a[6] == sum);
    assert(a[1] + a[4] + a[7] == sum);
    assert(a[2] + a[5] + a[8] == sum);

    // diagonal
    assert(a[0] + a[4] + a[8] == sum);
    assert(a[2] + a[4] + a[6] == sum);
    return;
}
```


* Compile the circuit and perform trusted setup

Execute ZoKrates docker, for example like this:

```
docker run -v /home/me/projects/mydemo/:/zokrates -ti zokrates/zokrates /bin/bash
```

Go to the `zokrates` directory and run:
```
zokrates compile -i magic_square.zok
zokrates setup
```

* Check files generated by ZoKrates

The file `verification.key` will now contain the verification key. The
key consists of four elliptic curve points $\alpha$, $\beta$,
$\gamma$, and $\delta$ plus an array of points $\gamma_{abc}$ - one
point per each public input of the verified circuit plus one extra point.


### Converting the Verifier into PyTeal Contract

* In the `zokrates` directory , execute conversion script:

```
python zokrates2algorand.py  compile_contract
```


The script generates a code snippet that can be pasted into our application:
(shortened)
```
  g2elems = Bytes("base16","0x0bf8...ad")
  g1elems = Bytes("base16","0x0f00...6a")
  gammaabc_0 = Bytes("base16","0x208f...ae5")
  gammaabc_1 = Bytes("base16","0x2582...c1")
  vkx = gammaabc_0
  x = B256ScalarMul(gammaabc_1, Arg(3))
  vkx = B256Add(vkx, x)
  g2 = Concat(Arg(1), g2elems)
  g1 = Concat(Arg(0), vkx, Arg(2), g1elems)
  return B256Pairing(g2, g1) == Int(1)
```

The snippet implements a `PyTeal` function that upon receiving the
public inputs in the `Arg` array starting at `Arg(3)` and a proof
(`Arg(0)` to `Arg(2)`) returns a boolean value. The value is `True` if
the proof is correct.

An example, how the proof can be integrated into a contract can be seen in [contracts.py](contracts.py) file.


### Generating a ZK Proof in ZoKrazes
* Solve the magic square puzzle for some $n$. For example for $n = 15$ a solution is:
```
| 2 | 7 | 6 |
| 9 | 5 | 1 |
| 4 | 3 | 8 |
```
The nine numbers of the solution are called witness and are secret. The sum $15$ is a public input.

* Run ZoKrates 

On the zokrates docker prompt run `Zokrates` and give him the witness and the public input:

```
zokrates compute-witness -a  2 7 6 9 5 1 4 3 8 15
zokrates generate-proof
```

* Check files generated by ZoKrates

The file `proof.json` contains the values of the proof (three elliptic
curve points $a$, $b$, and $c$ and an array of public inputs.

### Converting the Proof into PyTeal Contract Call

* In the `zokrates` directory , execute conversion script:

```
python zokrates2algorand.py  compile_proof
```


The script generates a code snippet encoding the proof that can be
pasted into our application call:
(shortened)
```
    args.append(binascii.unhexlify("2f8b..51"))
    args.append(binascii.unhexlify("25e4..b9"))
    args.append(binascii.unhexlify("26d3..4b"))
    args.append(binascii.unhexlify("0f"))
```

### Testing the contract

Start the sandbox, co to the  the root directory, and execute the demo:

```
python example.py
```

The contract will be executed. If the proof is correct, an ammount of 0.0001 algo will be transfered.

```
Successfully sent transaction with txID: VT5ABSGAYZ4PA6BC7OZA2JPNFWULDS7VREFB7AWKXAJNDVJNUIEA
Response: []
donor balances: {0: 99998000}
claimer balances: {0: 100001000} 

```

Try to tamper with the proof or public input. If you change anything,
the contract call fails.