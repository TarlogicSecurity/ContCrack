# ContCrack
This tiny C program demonstrates why reusing the same keystream for (even noisy) sensor data is a bad idea. It exploits the fact that the derivatives in time of the sensor data ara in general small, even in presence of noise. It will simulate multiple temperature readings during multiple days, xor them against a random keystream and, exploiting the aforementioned property, retrieve part of the encrypted data.

## Build
This program has been written in GNU/Linux, but it should run fine in any other Unix-like system. The command line to compile it is as simple as:

```
% gcc contcrack.c -o contcrack -lm
```

## Run
Just type:
```
% ./contcrack
```
And `contcrack` will generate a set of curves, encrypt them and attempt crack them using a simulated annealing optimizer.

## Files
Upon successful execution, `contcrack` will dump the following Octave files:

* `original.m`: original dataset.
* `encrypted.m`: encrypted dataset.
* `decrypted.m`: naively decrypted dataset, assuming that non-variying bits are zero (which is not necessarily true, although for this particular case it is)
* `improved.m`: truly decrypted dataset, up to certain uncertainty in the least significant bits.


