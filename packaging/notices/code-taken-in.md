## Code taken into BeeZip

### ARJ, ACE and ZOO

BeeZip's ARJ, ACE and ZOO readers began as the `arj`, `ace` and `zoo` modules of unarc-rs 0.8.1 (https://github.com/mkrueger/unarc-rs, MIT OR Apache-2.0, taken under MIT), rewritten into BeeZip's source; unarc-rs isn't a dependency. Its ACE module is itself a port of acefile 0.6 (https://github.com/droe/acefile, BSD-2-Clause), whose tables BeeZip's ACE cipher and decoder carry. The ARC and XAR readers are BeeZip's own.

unarc-rs's license, as BeeZip takes it:

```text
MIT License

Copyright (c) Mike Krüger

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

acefile's license, in full:

```text
# License and copyright

## Copyright

Copyright (c) 2017-2026, Daniel Roethlisberger and contributors.
All rights reserved.
Licensed under the 2-clause BSD license contained herein.


## Contributions

By contributing to the software, the contributor releases their
contribution under the license and copyright terms herein.  While
contributors retain copyright to their contributions, they grant the
main copyright holder of the software the irrevocable, transferable
right to relicense the software as a whole or in part, including their
contributions, under different open source licenses than the one
contained herein.


## License

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

1. Redistributions of source code must retain the above copyright
   notice, this list of conditions, and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


## Note

The ACE archive format and ACE compression and decompression
algorithms have been designed by Marcel Lemke.  The above copyright
notice and license does not constitute a claim of intellectual property
over ACE technology beyond the copyright of this python implementation.
```

### UnRAR

The UnRAR source BeeZip builds is the copy `unrar_sys` 0.5.8 vendors, which carries that crate's patches. Its license, in full:

```text
 ******    *****   ******   UnRAR - free utility for RAR archives
 **   **  **   **  **   **  ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 ******   *******  ******    License for use and distribution of
 **   **  **   **  **   **   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 **   **  **   **  **   **         FREE portable version
                                   ~~~~~~~~~~~~~~~~~~~~~

      The source code of UnRAR utility is freeware. This means:

   1. All copyrights to RAR and the utility UnRAR are exclusively
      owned by the author - Alexander Roshal.

   2. UnRAR source code may be used in any software to handle
      RAR archives without limitations free of charge, but cannot be
      used to develop RAR (WinRAR) compatible archiver and to
      re-create RAR compression algorithm, which is proprietary.
      Distribution of modified UnRAR source code in separate form
      or as a part of other software is permitted, provided that
      full text of this paragraph, starting from "UnRAR source code"
      words, is included in license, or in documentation if license
      is not available, and in source code comments of resulting package.

   3. The UnRAR utility may be freely distributed. It is allowed
      to distribute UnRAR inside of other software packages.

   4. THE RAR ARCHIVER AND THE UnRAR UTILITY ARE DISTRIBUTED "AS IS".
      NO WARRANTY OF ANY KIND IS EXPRESSED OR IMPLIED.  YOU USE AT 
      YOUR OWN RISK. THE AUTHOR WILL NOT BE LIABLE FOR DATA LOSS, 
      DAMAGES, LOSS OF PROFITS OR ANY OTHER KIND OF LOSS WHILE USING
      OR MISUSING THIS SOFTWARE.

   5. Installing and using the UnRAR utility signifies acceptance of
      these terms and conditions of the license.

   6. If you don't agree with terms of the license you must remove
      UnRAR files from your storage devices and cease to use the
      utility.

      Thank you for your interest in RAR and UnRAR.


                                            Alexander L. Roshal
```

### hadris-iso

BeeZip builds a patched copy of hadris-iso 3.0.0-rc.3 by hxyulin (MIT): `vendor/hadris-iso` in BeeZip's source, with its changes in `BEEZIP.md` there. Its license is with the Rust crates below.

### fstool

BeeZip builds a patched copy of fstool 0.5.2 by Karpelès Lab Inc. (MIT): `vendor/fstool` in BeeZip's source, trimmed to the file systems BeeZip reads through it, with its changes in `BEEZIP.md` there. Its license is with the Rust crates below.
