# cryptochallenge

My C solutions to the [Matasano Cryptopals Challenges](https://cryptopals.com).

Why? I started working on these way back in 2014 when I switched teams at my then-job into a team that specifically did cryptography and so wanted to sharpen up my skills. I've dusted this solution set off in 2020 as a hobbyist programming project (which I hope will excuse my shoddy makefile, among other things), but also so that I could have a reasonably large base of public source I can take credit for, as everything I've ever worked on professionally is closed source and employers increasingly expect candidates to provide open source code.

Why in C? At the time, my job was primary programming in C, and so it felt like the natural language to work in. C also makes it easiest to use some of the macOS system libraries I'm familiar with. Of course I'd otherwise never start any large new projects in C, especially cryptography ones, unless I had no choice. But, unsafe as it is, I still find C fun to work in.

## Building

This is a hobby project and has never been verified to work on anything but my personal MacBook. Invoking `make` should build and run a test suite. This mostly targets just `libc`, but also pulls in a couple macOS specific things, such as `CommonCrypto.framework` (for primitives like block ciphers) and `libxpc` (just for its handy dictionary type). It also uses Apple-specific C extensions for blocks, and I bet I wind up depending on some other macOS specific stuff. For instance I'm not sure if `arc4random` and its variants are available or equivalent on other Unixes.
