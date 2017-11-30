<!--
 
 README.md: yes, the license applies to this file too
 
 This file is part of Sweet B, a safe, compact, embeddable elliptic curve
 cryptography library.
 
 Sweet B is provided under the terms of the included LICENSE file. All
 other rights are reserved.
 
 Copyright 2017 Wearable Inc.
 
-->

![Sweet B Logo](sweet-b.svg)

Sweet B is a library which implements public key elliptic curve cryptography
(ECC) using the NIST P-256 and SECG secp256k1 curves. Sweet B is:

* *Safe:* known attack vectors have been accounted for, design decisions have
  been documented, and the API has been designed to eliminate the possibility of
  catastrophic misuse when possible.
* *Clear:* the library is thoroughly commented and unit tested, and is designed
  to be easy to read and review.
* *Compact:* the library is compact in code size, uses a minimal 512-byte
  working context, and does not assume that keys and other intermediary products
  can be allocated on the stack.

Sweet B is currently available for public review and testing, and will be
released under an open source license when we are confident that it is ready for
widespread use. You should consider using Sweet B if you need to implement
elliptic curve Diffie-Hellman shared-secret generation (ECDH) or elliptic curve
digital signature generation and verification (ECDSA) in a memory-constrained
environment. For instance, the P-256 curve is used in Bluetooth Low Energy
Security, and is often implemented on memory-constrained devices for this
purpose.

Secure system design depends on more than just the right choice of cryptographic
library. Commercial support for the use and adaptation of Sweet B is [available
from its authors](https://wearable.com/contact.html).

## Why is it called Sweet B?

Sweet B is a pun on both the Short Weierstrass form of elliptic curves and on
the NSA's [Suite B](https://en.wikipedia.org/wiki/NSA_Suite_B_Cryptography) set of cryptographic algorithms.

## Where did Sweet B come from?

Sweet B was developed by [Wearable Inc](https://wearable.com). We're opening
Sweet B for public review in advance of the release of
[Nanite](https://naniteproject.org/), our open-source operating system and
developer platform for Bluetooth Low Energy.

Suite B is derived in part from work supported by DARPA under SBIR contract
number D15PC00141.

## How does Sweet B protect against known attacks on ECC?

Sweet B provides mitigation for several classes of known faults and attacks:

* _Timing analyses_ reveal secret information by measuring the time that it
  takes to perform cryptographic operations. Sweet B prevents this by ensuring
  that all operations run in constant time with respect to the input data
  (though different curves have different performance characteristics).
* _Power analyses_ reveal secret information by measuring the amount of power
  consumed during cryptographic operations. Sweet B addresses this by using
  *randomized projective coordinates*, also called Z blinding. The special case
  of *zero value analysis* has been addressed by representing reduced integers
  modulo 𝑝 as integers within the range [1, 𝑝], ensuring that the points
  (0, ±√𝐵 ∙ 𝑍³, 𝑍) do not cause observable multiplications by
  low-Hamming-weight field elements.
* _Safe-error analyses_ reveal secret information by causing hardware faults
  during cryptographic operations and observing whether the fault affects the
  output. Sweet B mitigates these attacks through the use of a regular
  Montgomery ladder with no dummy computations prior to the final bit.
* _Per-message secret reuse_ causes the private key to be revealed to anyone
  receiving more than one signature with the same secret. Sweet B prevents this
  by providing an internal implementation of a deterministic random-bit
  generator (DRBG) using HMAC-SHA256 for per-message secret generation in ECDSA
  signing. When an externally seeded instance of the DRBG is provided, the
  private key and message are provided as additional input to the DRBG, ensuring
  that even in cases of entropy source failure, per-message secrets are never
  re-used. When no externally seeded instance is provided,
  [RFC6979](https://tools.ietf.org/html/rfc6979) deterministic signing is used.
  The internal HMAC-DRBG is also used for projective-coordinate randomization
  when no external entropy source is available.

It is impossible to guarantee that side-channel mitigations in a
portable C implementation will perform correctly with all compilers and with all
target platforms. If power and fault-injection mitigations are important for
your application, please [contact Wearable](https://wearable.com/contact.html)
for commercial support.

## What makes Sweet B different than other implementations?

Sweet B is designed to be simple, safe, compact, and embeddable. In order to be
as portable as possible, any word size from 8 to 64 bits may be used; you should
choose the word size that corresponds to the size of your hardware multiplier.
Sweet B does not assume that it's possible to store large amounts of working
state on the stack; instead, a separately allocated 512-byte working context is
required, which may be placed on the stack, heap allocated, or statically
allocated per the user's needs.

Simple, compact implementations of SHA256, HMAC-SHA256, and HMAC-DRBG are
provided both for internal use and for use in producing digests of data to be
signed or verified. You are also encouraged to use the HMAC-DRBG implementation
for random number generation in your system, assuming you have access to a
sufficient source of hardware entropy.

Sweet B uses Montgomery multiplication, which eliminates the need for separate
reduction steps. This makes it easier to produce a constant-time library
supporting multiple primes, and also makes Sweet B fast compared with other
embeddable implementations in C. However, there are faster implementations of
ECC if you have more working memory or more code storage available.

## How do I get started with Sweet B?

[`sb_sw_lib.h`](sb_sw_lib.h) is the main entry point for ECC operations. For
hashing and random number generation, see [`sb_sha256.h`](sb_sha256.h) and
[`sb_hmac_drbg.h`](sb_hmac_drbg.h). Each file contains a number of test cases;
if you compile Sweet B with `-DSB_TEST`, you can run them using the main routine
in [`sb_test.c`](sb_test.c).

[CMake](https://cmake.org/) build support is provided; to use it, create a
directory for your build, run `cmake` with the path to the Sweet B sources, and
then run `make` to build. To run the unit tests with the clang undefined
behavior sanitizer, pass `-DCMAKE_C_COMPILER=clang` to `cmake`.

## What license is Sweet B available under?

Sweet B is not yet open source! You are encouraged to experiment, review,
analyze, and test the library, and to share your findings with others, but you
are not allowed to use it in any situation where the security of anyone's data
depends on it. For the exact details, see the [`LICENSE.txt`](LICENSE.txt) file.
Once we are confident that it is ready for use, an official release will be made
under the [MPL 2.0](https://www.mozilla.org/en-US/MPL/2.0/). We believe this is
the best license choice for the library as it imposes few barriers to commercial
use while requiring distributors of modified versions to share their
modifications so they can be inspected by users.

## Are the NIST P-256 and SECG secp256k1 curves safe to use?

To the best of anyone's knowledge, yes. All public-key cryptography relies on
unproven assumptions about the difficulty of solving certain mathematical
problems; after more than three decades of research, there are no indications
that prime order elliptic curves of the short Weierstrass form used in Sweet B
are fundamentally weak or insecure.

There's been a fair amount of controversy about P-256 recently because of the
NSA's role in the specification of both P-256 and the deliberately backdoored
[Dual EC DRBG](https://en.wikipedia.org/wiki/Dual_EC_DRBG) algorithm. Because
one of the important parameters of P-256 was specified as a hash of a
supposedly-random string, some have theorized that the NSA may have tried a
large number of supposedly-random hashed strings until it found one that met its
criteria. However, the fact that the NSA had to resort to a clumsy and obvious
backdoor mechanism in Dual EC DRBG suggests that they do not have access to any
such mechanism of generating weak curves, and furthermore, it seems quite
unlikely that a large class of weak curves would go unnoticed by the academic
community in the almost 20 years since the NIST curve recommendations were
issued. If you feel uncomfortable with P-256 and have the ability to choose a
different curve for your application, the secp256k1 curve has no
supposedly-random constants and is suitable as an alternative.

Recently, there's also been a fair amount of interest in curves of the
Montgomery and Edwards forms; these curves have their own strengths, including
performance advantages, and weaknesses of their own which must be mitigated
through careful design and implementation choices. One cryptographer and
promoter of such curves has declared all short Weierstrass curves to be
"unsafe"; however, his analysis is at best seriously misleading, and includes
only criteria of his own choosing. The claims made of unsafety are answered as
follows:

* The rigidity argument has been addressed above. You might also consider that
  if you are choosing a curve because of the possibility that the NSA has secret
  knowledge of a large class of weak curves, you might accidentally pick such a
  curve even when following a "rigid" curve-specification procedure.
* The complex multiplication discriminant of secp256k1 permits an automorphism
  which can be used to improve the average running time of Pollard's ρ, but the
  rho method is faster yet on Montgomery and Edwards curves of equivalent
  prime-field size due to the smaller size of their cryptographic subgroup.
* The Montgomery ladder used in Sweet B is non-exceptional for all input scalars
  ∉ {-2, -1, 0, 1} mod 𝑛. These input scalars are easily checked for, and the
  probability of one of these scalars occurring in HMAC-DRBG output is
  infinitesimal.
* Complete addition formulae are not relevant to actual cryptographic software.
  Even implementations of twisted Edwards curves use [non-unified addition and
  doubling
  formulae](https://iacr.org/archive/asiacrypt2008/53500329/53500329.pdf) in
  practice for efficiency purposes.
* Indistinguishability of points from random strings is not a requirement for
  most protocols. This requirement is motivated by certain censorship-avoidance
  applications, but not needed for many other applications, and to the best of
  our knowledge, there is no proof that such a scheme can't be developed for
  short Weierstrass curves.

We could easily add additional criteria of our own choosing and decide that
other curves are "unsafe". For instance, if avoidance of special cases is a
concern, we could decide that primes `≡ 1 mod 4` are unsafe due to the extra
(and irregular) step required in point decompression. Similarly, we could
declare that curves with a cofactor `≠ 1` are unsafe due to the extra care
required in avoiding small-subgroup attacks. Neither of these criteria make
these curves unsafe in practice, but they necessitate careful attention in the
implementation and use of these curves, as is the case for all cryptographic
software.

Our point is not to suggest the use of P-256 or secp256k1 over other curves;
rather, if you have a need to use either of these curves, you should not be
concerned as long as your implementation was developed with appropriate care.

## Annotated Bibliography

Neal Koblitz. A Course in Number Theory and Cryptography. Springer-Verlag, 1994.

> This is a rather old text, and the section on elliptic curves is dated.
> However, it remains an outstanding reference for any discussion of finite
> fields.

Alfred J. Menezes, Paul C. van Oorschot, and Scott A. Vanstone. [Handbook of
Applied Cryptography](http://cacr.uwaterloo.ca/hac/). CRC Press, 1996.

> Another older text, but the chapter on efficient implementation remains a
> worthwhile reference for basic field arithmetic algorithms.

Jean-Sébastien Coron. [Resistance Against Differential Power Analysis For
Elliptic Curve
Cryptosystems](http://www.crypto-uni.lu/jscoron/publications/dpaecc.pdf). In
_Cryptographic Hardware and Embedded Systems (CHES) 1999_.

> Introduces several countermeasures against power analyses, the third of which
> is the randomized projective coordinate technique used in Sweet B (often
> described as "Coron's third countermeasure").

Tetsuya Izu, Bodo Möller, and Tsuyoshi Takagi. [Improved Elliptic Curve
Multiplication Methods Resistant against Side Channel
Attacks](http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.436.831&rep=rep1&type=pdf).
In _Progress in Cryptology — INDOCRYPT 2002_.

> Discusses the SPA and DPA-resistance of the Montgomery ladder for elliptic curves.

Raveen R. Goundar, Marc Joye, Atsuko Miyaji, Matthieu Rivain, and Alexandre
Venelli. [Scalar multiplication on Weierstraß elliptic curves from Co-Z
arithmetic](http://www.matthieurivain.com/files/jcen11b.pdf). In _Journal of
Cryptographic Engineering, Vol. 1, 161 (2011)_.

> Introduces the co-Z Montgomery ladder on Weierstrass curves, and discusses its
> derivation.

 Matthieu Rivain. [Fast and Regular Algorithms for Scalar Multiplication over
 Elliptic Curves](https://eprint.iacr.org/2011/338.pdf). _IACR Cryptology ePrint
 Archive, Report 2011/338_.

 > The main reference for Sweet B. Describes the co-Z addition and initial
 > affine-to-Jacobian point doubling formulae implemented in the library.

Shay Gueron and Vlad Krasnov. [Fast prime field elliptic-curve cryptography with
256-bit primes](https://eprint.iacr.org/2013/816.pdf). In _Journal of
Cryptographic Engineering, Vol. 5, 141 (2011)_.

> Discusses the use of Montgomery multiplication with the P-256 field prime,
> specifically due to its "Montgomery friendly" property.