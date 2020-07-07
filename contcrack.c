/*
 * contcrack.c: exploit derivative information of an encrypted noisy curve
 * to deduce keystream.
 *
 * Gonzalo J. Carracedo - gonzalo.carracedo@tarlogic.com
 * 
 * Copyright 2020 Tarlogic Security
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 * 
 * 3. Neither the name of the copyright holder nor the names of its contributors
 * may be used to endorse or promote products derived from this software without
 * specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include <stdint.h>
#include <time.h>
#include <assert.h>

#define MEASURES  (6 * 60)
#define DAYS      (100)
#define ITERS     30
#define BMAX      8
#define BITCYCLES 6

#define K 10
#define T0 30

typedef int32_t history_t[DAYS][MEASURES];

history_t data;
uint32_t keys[MEASURES];

/* Input data */
history_t encrypted;

/* Cracker state */
float    mean[MEASURES][32];
uint32_t mask[MEASURES];
history_t decrypted;

void
init_keys(void)
{
  int i = 0;

  for (i = 0; i < MEASURES; ++i)
    keys[i] = rand() * rand();
}

float
srandf(void)
{
  return .5 - (float) rand() / (float) RAND_MAX;
}

float
randf(void)
{
  return srandf() + .5;
}

void
init_data(void)
{
  int i, j;
  float phase;
  float ampl;
  float mean;
  
  for (j = 0; j < DAYS; ++j) {
    mean  = 20 + 20 * srandf();
    ampl  = 6  + 5 * srandf();
    phase = .3 * M_PI * srandf();
    
    for (i = 0; i < MEASURES; ++i) {
      data[j][i] = round(
        (mean
         + ampl * sin(phase + (float) i / (float) MEASURES * M_PI)
         + 1 * srandf())
        * 10);
      encrypted[j][i] = data[j][i] ^ keys[i];
    }
  }
}

void
dump_data(const char *path, const history_t *hist)
{
  FILE *fp;
  int i, j;
  
  if ((fp = fopen(path, "w")) == NULL)
    abort();

  fprintf(fp, "D = .1 * [\n");
  for (j = 0; j < DAYS; ++j) {
    for (i = 0; i < MEASURES; ++i)
      fprintf(fp, " %d", (*hist)[j][i]);
    fprintf(fp, ";\n");
  }
  
  fprintf(fp, "];");
  fclose(fp);
}

int
apply_mask(void)
{
  int i, j;
  int max = 0;
  
  for (i = 0; i < MEASURES; ++i)
    for (j = 0; j < DAYS; ++j) {
      decrypted[j][i] = encrypted[j][i] ^ mask[i];
      if (max < ceil(log2(decrypted[j][i])))
        max = ceil(log2(decrypted[j][i]));
    }

  return max;
}

void
compute_bit_mean(void)
{
  int i, j, k;

  memset(mean, 0, sizeof(mean));
  
  for (i = 0; i < MEASURES; ++i) {
    for (j = 0; j < DAYS; ++j) {
      for (k = 0; k < 32; ++k) {
        mean[i][k] += (1 & (encrypted[j][i] >> k)) / (float) DAYS;
      }
    }

    mask[i] = 0;
    for (k = 0; k < 32; ++k) {
      if (mean[i][k] >= .5)
        mask[i] |= 1 << k;
    }
  }

  apply_mask();
}

float
history_dispersion(const history_t *hist)
{
  int i, j;
  float diff_acc = 0;
  float diff;
  float metric;
  
  for (j = 0; j < DAYS; ++j) {
    metric = 0;
    
    for (i = 1; i < MEASURES; ++i) {
      diff = (float) ((*hist)[j][i] - (*hist)[j][i - 1]);
      diff *= diff;
      metric += diff;
    }

    diff_acc += metric;
  }

  return diff_acc / (DAYS * (MEASURES - 1));
}

int
keep(float E0, float E1, float T)
{
  if (E1 < E0)
    return 1;
  else
    return exp(-(E1 - E0) / T) >= randf();
}

void
adjust_mask_bit(int bit, float T)
{
  int i = 0;
  int32_t toggle = bit == BMAX ? ~((1 << bit) - 1) : 1 << bit;
  float old_disp = history_dispersion(&decrypted);
  float curr_disp = old_disp;
  float disp = 0;

  for (i = 0; i < MEASURES; ++i) {
    mask[i] ^= toggle;

    apply_mask();
    disp = history_dispersion(&decrypted);

    if (keep(curr_disp, disp, T)) {
      curr_disp = disp;
    } else {
      /* Bad idea. Undo */
      mask[i] ^= toggle;
    }
  }

  apply_mask();
  curr_disp = history_dispersion(&decrypted);

  printf(
    "\033[2KAdjusting bit %d: %g -> %g (%g%%) (%s)\r",
    bit,
    old_disp,
    curr_disp,
    100 * (old_disp - curr_disp) / old_disp,
    old_disp < curr_disp ? "\033[1;31mHEAT\033[0m" : "\033[1;36mCOOL\033[0m");
  fflush(stdout);
}

int
main(void)
{
  int i, j;
  float tipdisp;
  float kT0;
  float T = 0;
  int bit;
  
  init_keys();
  init_data();

  
  dump_data("original.m", &data);
  dump_data("encrypted.m", &encrypted);
  compute_bit_mean();

  
  printf("Dispersion (original): %g\n", history_dispersion(&data));
  printf("Dispersion (encrypted): %g\n", history_dispersion(&encrypted));
  
  dump_data("decrypted.m", &decrypted);

  tipdisp = history_dispersion(&decrypted);
  printf("Dispersion (decrypted): %g\n", tipdisp);

  memcpy(encrypted, decrypted, sizeof(decrypted));
  compute_bit_mean();
  
  kT0 = ITERS / (tipdisp) * .25;
  printf("kT0: %g\n", kT0);

  srand(time(NULL));

  for (j = 0; j < ITERS; ++j) {
    //T = kT0 / sqrt(j + 1);
    T = T0 * (exp(-K * j / (float) (ITERS - 1)) - exp(-K));
    printf("\033[2KIterating (%d/%d) T = %g K\n", j + 1, ITERS, T);

    for (i = 0; i <= BITCYCLES * BMAX; ++i) {
      bit = round(randf() * BMAX);
      adjust_mask_bit(bit, T);
    }
    dump_data("improved.m", &decrypted);
  }
}
