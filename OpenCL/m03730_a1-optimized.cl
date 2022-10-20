/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_simd.cl)
#include M2S(INCLUDE_PATH/inc_hash_md5.cl)
#endif

#if   VECT_SIZE == 1
#define uint_to_hex_upper8(i) make_u32x (u_bin2asc[(i)])
#elif VECT_SIZE == 2
#define uint_to_hex_upper8(i) make_u32x (u_bin2asc[(i).s0], u_bin2asc[(i).s1])
#elif VECT_SIZE == 4
#define uint_to_hex_upper8(i) make_u32x (u_bin2asc[(i).s0], u_bin2asc[(i).s1], u_bin2asc[(i).s2], u_bin2asc[(i).s3])
#elif VECT_SIZE == 8
#define uint_to_hex_upper8(i) make_u32x (u_bin2asc[(i).s0], u_bin2asc[(i).s1], u_bin2asc[(i).s2], u_bin2asc[(i).s3], u_bin2asc[(i).s4], u_bin2asc[(i).s5], u_bin2asc[(i).s6], u_bin2asc[(i).s7])
#elif VECT_SIZE == 16
#define uint_to_hex_upper8(i) make_u32x (u_bin2asc[(i).s0], u_bin2asc[(i).s1], u_bin2asc[(i).s2], u_bin2asc[(i).s3], u_bin2asc[(i).s4], u_bin2asc[(i).s5], u_bin2asc[(i).s6], u_bin2asc[(i).s7], u_bin2asc[(i).s8], u_bin2asc[(i).s9], u_bin2asc[(i).sa], u_bin2asc[(i).sb], u_bin2asc[(i).sc], u_bin2asc[(i).sd], u_bin2asc[(i).se], u_bin2asc[(i).sf])
#endif

typedef struct md5_double_salt
{
  u32 salt1_buf[64];
  int salt1_len;

  u32 salt2_buf[64];
  int salt2_len;

} md5_double_salt_t;

KERNEL_FQ void m03730_m04 (KERN_ATTR_BASIC_ESALT (md5_double_salt_t))
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * bin2asc uppercase table
   */
   
  LOCAL_VK u32 u_bin2asc[256];

  for (u32 j = lid; j < 256; j += lsz)
  {
    const u32 i0 = (j >> 0) & 15;
    const u32 i1 = (j >> 4) & 15;

    u_bin2asc[j] = ((i0 < 10) ? '0' + i0 : 'A' - 10 + i0) << 8
                 | ((i1 < 10) ? '0' + i1 : 'A' - 10 + i1) << 0;
  }

  SYNC_THREADS ();

  if (gid >= GID_CNT) return;

  /**
   * base
   */

  u32 pw_buf0[4];
  u32 pw_buf1[4];

  pw_buf0[0] = pws[gid].i[0];
  pw_buf0[1] = pws[gid].i[1];
  pw_buf0[2] = pws[gid].i[2];
  pw_buf0[3] = pws[gid].i[3];
  pw_buf1[0] = pws[gid].i[4];
  pw_buf1[1] = pws[gid].i[5];
  pw_buf1[2] = pws[gid].i[6];
  pw_buf1[3] = pws[gid].i[7];

  const u32 pw_l_len = pws[gid].pw_len & 63;

  /**
   * salt1
   */

  u32 salt1_buf0[4];
  u32 salt1_buf1[4];
  u32 salt1_buf2[4];
  u32 salt1_buf3[4];

  salt1_buf0[0] = esalt_bufs[DIGESTS_OFFSET_HOST].salt1_buf[ 0];
  salt1_buf0[1] = esalt_bufs[DIGESTS_OFFSET_HOST].salt1_buf[ 1];
  salt1_buf0[2] = esalt_bufs[DIGESTS_OFFSET_HOST].salt1_buf[ 2];
  salt1_buf0[3] = esalt_bufs[DIGESTS_OFFSET_HOST].salt1_buf[ 3];
  salt1_buf1[0] = esalt_bufs[DIGESTS_OFFSET_HOST].salt1_buf[ 4];
  salt1_buf1[1] = esalt_bufs[DIGESTS_OFFSET_HOST].salt1_buf[ 5];
  salt1_buf1[2] = esalt_bufs[DIGESTS_OFFSET_HOST].salt1_buf[ 6];
  salt1_buf1[3] = esalt_bufs[DIGESTS_OFFSET_HOST].salt1_buf[ 7];
  salt1_buf2[0] = esalt_bufs[DIGESTS_OFFSET_HOST].salt1_buf[ 8];
  salt1_buf2[1] = esalt_bufs[DIGESTS_OFFSET_HOST].salt1_buf[ 9];
  salt1_buf2[2] = esalt_bufs[DIGESTS_OFFSET_HOST].salt1_buf[10];
  salt1_buf2[3] = esalt_bufs[DIGESTS_OFFSET_HOST].salt1_buf[11];
  salt1_buf3[0] = esalt_bufs[DIGESTS_OFFSET_HOST].salt1_buf[12];
  salt1_buf3[1] = esalt_bufs[DIGESTS_OFFSET_HOST].salt1_buf[13];
  salt1_buf3[2] = esalt_bufs[DIGESTS_OFFSET_HOST].salt1_buf[14];
  salt1_buf3[3] = esalt_bufs[DIGESTS_OFFSET_HOST].salt1_buf[15];

  const u32 salt1_len = esalt_bufs[DIGESTS_OFFSET_HOST].salt1_len;

  /**
   * salt2
   */

  u32 salt2_buf0[4];
  u32 salt2_buf1[4];
  u32 salt2_buf2[4];
  u32 salt2_buf3[4];

  salt2_buf0[0] = esalt_bufs[DIGESTS_OFFSET_HOST].salt2_buf[ 0];
  salt2_buf0[1] = esalt_bufs[DIGESTS_OFFSET_HOST].salt2_buf[ 1];
  salt2_buf0[2] = esalt_bufs[DIGESTS_OFFSET_HOST].salt2_buf[ 2];
  salt2_buf0[3] = esalt_bufs[DIGESTS_OFFSET_HOST].salt2_buf[ 3];
  salt2_buf1[0] = esalt_bufs[DIGESTS_OFFSET_HOST].salt2_buf[ 4];
  salt2_buf1[1] = esalt_bufs[DIGESTS_OFFSET_HOST].salt2_buf[ 5];
  salt2_buf1[2] = esalt_bufs[DIGESTS_OFFSET_HOST].salt2_buf[ 6];
  salt2_buf1[3] = esalt_bufs[DIGESTS_OFFSET_HOST].salt2_buf[ 7];
  salt2_buf2[0] = esalt_bufs[DIGESTS_OFFSET_HOST].salt2_buf[ 8];
  salt2_buf2[1] = esalt_bufs[DIGESTS_OFFSET_HOST].salt2_buf[ 9];
  salt2_buf2[2] = esalt_bufs[DIGESTS_OFFSET_HOST].salt2_buf[10];
  salt2_buf2[3] = esalt_bufs[DIGESTS_OFFSET_HOST].salt2_buf[11];
  salt2_buf3[0] = esalt_bufs[DIGESTS_OFFSET_HOST].salt2_buf[12];
  salt2_buf3[1] = esalt_bufs[DIGESTS_OFFSET_HOST].salt2_buf[13];
  salt2_buf3[2] = esalt_bufs[DIGESTS_OFFSET_HOST].salt2_buf[14];
  salt2_buf3[3] = esalt_bufs[DIGESTS_OFFSET_HOST].salt2_buf[15];

  const u32 salt2_len = esalt_bufs[DIGESTS_OFFSET_HOST].salt2_len;

  const u32 final_len = salt1_len + 32;

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32x pw_r_len = pwlenx_create_combt (combs_buf, il_pos) & 63;

    const u32x pw_len = (pw_l_len + pw_r_len) & 63;

    /**
     * concat password candidate
     */

    u32x wordl0[4] = { 0 };
    u32x wordl1[4] = { 0 };
    u32x wordl2[4] = { 0 };
    u32x wordl3[4] = { 0 };

    wordl0[0] = pw_buf0[0];
    wordl0[1] = pw_buf0[1];
    wordl0[2] = pw_buf0[2];
    wordl0[3] = pw_buf0[3];
    wordl1[0] = pw_buf1[0];
    wordl1[1] = pw_buf1[1];
    wordl1[2] = pw_buf1[2];
    wordl1[3] = pw_buf1[3];

    u32x wordr0[4] = { 0 };
    u32x wordr1[4] = { 0 };
    u32x wordr2[4] = { 0 };
    u32x wordr3[4] = { 0 };

    wordr0[0] = ix_create_combt (combs_buf, il_pos, 0);
    wordr0[1] = ix_create_combt (combs_buf, il_pos, 1);
    wordr0[2] = ix_create_combt (combs_buf, il_pos, 2);
    wordr0[3] = ix_create_combt (combs_buf, il_pos, 3);
    wordr1[0] = ix_create_combt (combs_buf, il_pos, 4);
    wordr1[1] = ix_create_combt (combs_buf, il_pos, 5);
    wordr1[2] = ix_create_combt (combs_buf, il_pos, 6);
    wordr1[3] = ix_create_combt (combs_buf, il_pos, 7);

    if (COMBS_MODE == COMBINATOR_MODE_BASE_LEFT)
    {
      switch_buffer_by_offset_le_VV (wordr0, wordr1, wordr2, wordr3, pw_l_len);
    }
    else
    {
      switch_buffer_by_offset_le_VV (wordl0, wordl1, wordl2, wordl3, pw_r_len);
    }

    u32x w0[4];
    u32x w1[4];
    u32x w2[4];
    u32x w3[4];

    w0[0] = wordl0[0] | wordr0[0];
    w0[1] = wordl0[1] | wordr0[1];
    w0[2] = wordl0[2] | wordr0[2];
    w0[3] = wordl0[3] | wordr0[3];
    w1[0] = wordl1[0] | wordr1[0];
    w1[1] = wordl1[1] | wordr1[1];
    w1[2] = wordl1[2] | wordr1[2];
    w1[3] = wordl1[3] | wordr1[3];
    w2[0] = wordl2[0] | wordr2[0];
    w2[1] = wordl2[1] | wordr2[1];
    w2[2] = wordl2[2] | wordr2[2];
    w2[3] = wordl2[3] | wordr2[3];
    w3[0] = wordl3[0] | wordr3[0];
    w3[1] = wordl3[1] | wordr3[1];
    w3[2] = pw_len * 8;
    w3[3] = 0;

    /**
     * prepend salt2
     */

    switch_buffer_by_offset_le (w0, w1, w2, w3, salt2_len);

    const u32x pw_salt_len = pw_len + salt2_len;

    w0[0] |= salt2_buf0[0];
    w0[1] |= salt2_buf0[1];
    w0[2] |= salt2_buf0[2];
    w0[3] |= salt2_buf0[3];
    w1[0] |= salt2_buf1[0];
    w1[1] |= salt2_buf1[1];
    w1[2] |= salt2_buf1[2];
    w1[3] |= salt2_buf1[3];
    w2[0] |= salt2_buf2[0];
    w2[1] |= salt2_buf2[1];
    w2[2] |= salt2_buf2[2];
    w2[3] |= salt2_buf2[3];
    w3[0] |= salt2_buf3[0];
    w3[1] |= salt2_buf3[1];
    w3[2]  = pw_salt_len * 8;
    w3[3]  = 0;

    /**
     * md5
     */

    u32x a = MD5M_A;
    u32x b = MD5M_B;
    u32x c = MD5M_C;
    u32x d = MD5M_D;

    MD5_STEP (MD5_Fo, a, b, c, d, w0[0], MD5C00, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w0[1], MD5C01, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w0[2], MD5C02, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w0[3], MD5C03, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, w1[0], MD5C04, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w1[1], MD5C05, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w1[2], MD5C06, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w1[3], MD5C07, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, w2[0], MD5C08, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w2[1], MD5C09, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w2[2], MD5C0a, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w2[3], MD5C0b, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, w3[0], MD5C0c, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w3[1], MD5C0d, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w3[2], MD5C0e, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w3[3], MD5C0f, MD5S03);

    MD5_STEP (MD5_Go, a, b, c, d, w0[1], MD5C10, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w1[2], MD5C11, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w2[3], MD5C12, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w0[0], MD5C13, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, w1[1], MD5C14, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w2[2], MD5C15, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w3[3], MD5C16, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w1[0], MD5C17, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, w2[1], MD5C18, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w3[2], MD5C19, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w0[3], MD5C1a, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w2[0], MD5C1b, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, w3[1], MD5C1c, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w0[2], MD5C1d, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w1[3], MD5C1e, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w3[0], MD5C1f, MD5S13);

    u32x t;

    MD5_STEP (MD5_H1, a, b, c, d, w1[1], MD5C20, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, w2[0], MD5C21, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, w2[3], MD5C22, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, w3[2], MD5C23, MD5S23);
    MD5_STEP (MD5_H1, a, b, c, d, w0[1], MD5C24, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, w1[0], MD5C25, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, w1[3], MD5C26, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, w2[2], MD5C27, MD5S23);
    MD5_STEP (MD5_H1, a, b, c, d, w3[1], MD5C28, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, w0[0], MD5C29, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, w0[3], MD5C2a, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, w1[2], MD5C2b, MD5S23);
    MD5_STEP (MD5_H1, a, b, c, d, w2[1], MD5C2c, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, w3[0], MD5C2d, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, w3[3], MD5C2e, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, w0[2], MD5C2f, MD5S23);

    MD5_STEP (MD5_I , a, b, c, d, w0[0], MD5C30, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w1[3], MD5C31, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w3[2], MD5C32, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w1[1], MD5C33, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, w3[0], MD5C34, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w0[3], MD5C35, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w2[2], MD5C36, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w0[1], MD5C37, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, w2[0], MD5C38, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w3[3], MD5C39, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w1[2], MD5C3a, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w3[1], MD5C3b, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, w1[0], MD5C3c, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w2[3], MD5C3d, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w0[2], MD5C3e, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w2[1], MD5C3f, MD5S33);

    a += make_u32x (MD5M_A);
    b += make_u32x (MD5M_B);
    c += make_u32x (MD5M_C);
    d += make_u32x (MD5M_D);

    w0[0] = uint_to_hex_upper8 ((a >>  0) & 255) <<  0
          | uint_to_hex_upper8 ((a >>  8) & 255) << 16;
    w0[1] = uint_to_hex_upper8 ((a >> 16) & 255) <<  0
          | uint_to_hex_upper8 ((a >> 24) & 255) << 16;
    w0[2] = uint_to_hex_upper8 ((b >>  0) & 255) <<  0
          | uint_to_hex_upper8 ((b >>  8) & 255) << 16;
    w0[3] = uint_to_hex_upper8 ((b >> 16) & 255) <<  0
          | uint_to_hex_upper8 ((b >> 24) & 255) << 16;
    w1[0] = uint_to_hex_upper8 ((c >>  0) & 255) <<  0
          | uint_to_hex_upper8 ((c >>  8) & 255) << 16;
    w1[1] = uint_to_hex_upper8 ((c >> 16) & 255) <<  0
          | uint_to_hex_upper8 ((c >> 24) & 255) << 16;
    w1[2] = uint_to_hex_upper8 ((d >>  0) & 255) <<  0
          | uint_to_hex_upper8 ((d >>  8) & 255) << 16;
    w1[3] = uint_to_hex_upper8 ((d >> 16) & 255) <<  0
          | uint_to_hex_upper8 ((d >> 24) & 255) << 16;
    w2[0] = 0x80;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 0;

    /**
     * prepend salt1
     */

    switch_buffer_by_offset_le (w0, w1, w2, w3, salt1_len);

    w3[2] = final_len * 8;
    w3[3] = 0;

    w0[0] |= salt1_buf0[0];
    w0[1] |= salt1_buf0[1];
    w0[2] |= salt1_buf0[2];
    w0[3] |= salt1_buf0[3];
    w1[0] |= salt1_buf1[0];
    w1[1] |= salt1_buf1[1];
    w1[2] |= salt1_buf1[2];
    w1[3] |= salt1_buf1[3];
    w2[0] |= salt1_buf2[0];
    w2[1] |= salt1_buf2[1];
    w2[2] |= salt1_buf2[2];
    w2[3] |= salt1_buf2[3];
    w3[0] |= salt1_buf3[0];
    w3[1] |= salt1_buf3[1];
    w3[2] |= salt1_buf3[2];
    w3[3] |= salt1_buf3[3];

    /**
     * md5
     */

    a = MD5M_A;
    b = MD5M_B;
    c = MD5M_C;
    d = MD5M_D;

    MD5_STEP (MD5_Fo, a, b, c, d, w0[0], MD5C00, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w0[1], MD5C01, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w0[2], MD5C02, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w0[3], MD5C03, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, w1[0], MD5C04, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w1[1], MD5C05, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w1[2], MD5C06, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w1[3], MD5C07, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, w2[0], MD5C08, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w2[1], MD5C09, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w2[2], MD5C0a, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w2[3], MD5C0b, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, w3[0], MD5C0c, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w3[1], MD5C0d, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w3[2], MD5C0e, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w3[3], MD5C0f, MD5S03);

    MD5_STEP (MD5_Go, a, b, c, d, w0[1], MD5C10, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w1[2], MD5C11, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w2[3], MD5C12, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w0[0], MD5C13, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, w1[1], MD5C14, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w2[2], MD5C15, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w3[3], MD5C16, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w1[0], MD5C17, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, w2[1], MD5C18, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w3[2], MD5C19, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w0[3], MD5C1a, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w2[0], MD5C1b, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, w3[1], MD5C1c, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w0[2], MD5C1d, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w1[3], MD5C1e, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w3[0], MD5C1f, MD5S13);

    MD5_STEP (MD5_H1, a, b, c, d, w1[1], MD5C20, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, w2[0], MD5C21, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, w2[3], MD5C22, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, w3[2], MD5C23, MD5S23);
    MD5_STEP (MD5_H1, a, b, c, d, w0[1], MD5C24, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, w1[0], MD5C25, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, w1[3], MD5C26, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, w2[2], MD5C27, MD5S23);
    MD5_STEP (MD5_H1, a, b, c, d, w3[1], MD5C28, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, w0[0], MD5C29, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, w0[3], MD5C2a, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, w1[2], MD5C2b, MD5S23);
    MD5_STEP (MD5_H1, a, b, c, d, w2[1], MD5C2c, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, w3[0], MD5C2d, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, w3[3], MD5C2e, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, w0[2], MD5C2f, MD5S23);

    MD5_STEP (MD5_I , a, b, c, d, w0[0], MD5C30, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w1[3], MD5C31, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w3[2], MD5C32, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w1[1], MD5C33, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, w3[0], MD5C34, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w0[3], MD5C35, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w2[2], MD5C36, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w0[1], MD5C37, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, w2[0], MD5C38, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w3[3], MD5C39, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w1[2], MD5C3a, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w3[1], MD5C3b, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, w1[0], MD5C3c, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w2[3], MD5C3d, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w0[2], MD5C3e, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w2[1], MD5C3f, MD5S33);

    COMPARE_M_SIMD (a, d, c, b);
  }
}

KERNEL_FQ void m03730_m08 (KERN_ATTR_BASIC_ESALT (md5_double_salt_t))
{
}

KERNEL_FQ void m03730_m16 (KERN_ATTR_BASIC_ESALT (md5_double_salt_t))
{
}

KERNEL_FQ void m03730_s04 (KERN_ATTR_BASIC_ESALT (md5_double_salt_t))
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * bin2asc uppercase table
   */
   
  LOCAL_VK u32 u_bin2asc[256];

  for (u32 j = lid; j < 256; j += lsz)
  {
    const u32 i0 = (j >> 0) & 15;
    const u32 i1 = (j >> 4) & 15;

    u_bin2asc[j] = ((i0 < 10) ? '0' + i0 : 'A' - 10 + i0) << 8
                 | ((i1 < 10) ? '0' + i1 : 'A' - 10 + i1) << 0;
  }

  SYNC_THREADS ();

  if (gid >= GID_CNT) return;

  /**
   * base
   */

  u32 pw_buf0[4];
  u32 pw_buf1[4];

  pw_buf0[0] = pws[gid].i[0];
  pw_buf0[1] = pws[gid].i[1];
  pw_buf0[2] = pws[gid].i[2];
  pw_buf0[3] = pws[gid].i[3];
  pw_buf1[0] = pws[gid].i[4];
  pw_buf1[1] = pws[gid].i[5];
  pw_buf1[2] = pws[gid].i[6];
  pw_buf1[3] = pws[gid].i[7];

  const u32 pw_l_len = pws[gid].pw_len & 63;

  /**
   * salt1
   */

  u32 salt1_buf0[4];
  u32 salt1_buf1[4];
  u32 salt1_buf2[4];
  u32 salt1_buf3[4];

  salt1_buf0[0] = esalt_bufs[DIGESTS_OFFSET_HOST].salt1_buf[ 0];
  salt1_buf0[1] = esalt_bufs[DIGESTS_OFFSET_HOST].salt1_buf[ 1];
  salt1_buf0[2] = esalt_bufs[DIGESTS_OFFSET_HOST].salt1_buf[ 2];
  salt1_buf0[3] = esalt_bufs[DIGESTS_OFFSET_HOST].salt1_buf[ 3];
  salt1_buf1[0] = esalt_bufs[DIGESTS_OFFSET_HOST].salt1_buf[ 4];
  salt1_buf1[1] = esalt_bufs[DIGESTS_OFFSET_HOST].salt1_buf[ 5];
  salt1_buf1[2] = esalt_bufs[DIGESTS_OFFSET_HOST].salt1_buf[ 6];
  salt1_buf1[3] = esalt_bufs[DIGESTS_OFFSET_HOST].salt1_buf[ 7];
  salt1_buf2[0] = esalt_bufs[DIGESTS_OFFSET_HOST].salt1_buf[ 8];
  salt1_buf2[1] = esalt_bufs[DIGESTS_OFFSET_HOST].salt1_buf[ 9];
  salt1_buf2[2] = esalt_bufs[DIGESTS_OFFSET_HOST].salt1_buf[10];
  salt1_buf2[3] = esalt_bufs[DIGESTS_OFFSET_HOST].salt1_buf[11];
  salt1_buf3[0] = esalt_bufs[DIGESTS_OFFSET_HOST].salt1_buf[12];
  salt1_buf3[1] = esalt_bufs[DIGESTS_OFFSET_HOST].salt1_buf[13];
  salt1_buf3[2] = esalt_bufs[DIGESTS_OFFSET_HOST].salt1_buf[14];
  salt1_buf3[3] = esalt_bufs[DIGESTS_OFFSET_HOST].salt1_buf[15];

  const u32 salt1_len = esalt_bufs[DIGESTS_OFFSET_HOST].salt1_len;

  /**
   * salt2
   */

  u32 salt2_buf0[4];
  u32 salt2_buf1[4];
  u32 salt2_buf2[4];
  u32 salt2_buf3[4];

  salt2_buf0[0] = esalt_bufs[DIGESTS_OFFSET_HOST].salt2_buf[ 0];
  salt2_buf0[1] = esalt_bufs[DIGESTS_OFFSET_HOST].salt2_buf[ 1];
  salt2_buf0[2] = esalt_bufs[DIGESTS_OFFSET_HOST].salt2_buf[ 2];
  salt2_buf0[3] = esalt_bufs[DIGESTS_OFFSET_HOST].salt2_buf[ 3];
  salt2_buf1[0] = esalt_bufs[DIGESTS_OFFSET_HOST].salt2_buf[ 4];
  salt2_buf1[1] = esalt_bufs[DIGESTS_OFFSET_HOST].salt2_buf[ 5];
  salt2_buf1[2] = esalt_bufs[DIGESTS_OFFSET_HOST].salt2_buf[ 6];
  salt2_buf1[3] = esalt_bufs[DIGESTS_OFFSET_HOST].salt2_buf[ 7];
  salt2_buf2[0] = esalt_bufs[DIGESTS_OFFSET_HOST].salt2_buf[ 8];
  salt2_buf2[1] = esalt_bufs[DIGESTS_OFFSET_HOST].salt2_buf[ 9];
  salt2_buf2[2] = esalt_bufs[DIGESTS_OFFSET_HOST].salt2_buf[10];
  salt2_buf2[3] = esalt_bufs[DIGESTS_OFFSET_HOST].salt2_buf[11];
  salt2_buf3[0] = esalt_bufs[DIGESTS_OFFSET_HOST].salt2_buf[12];
  salt2_buf3[1] = esalt_bufs[DIGESTS_OFFSET_HOST].salt2_buf[13];
  salt2_buf3[2] = esalt_bufs[DIGESTS_OFFSET_HOST].salt2_buf[14];
  salt2_buf3[3] = esalt_bufs[DIGESTS_OFFSET_HOST].salt2_buf[15];

  const u32 salt2_len = esalt_bufs[DIGESTS_OFFSET_HOST].salt2_len;

  const u32 final_len = salt1_len + 32;

  /**
   * digest
   */

  const u32 search[4] =
  {
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R0],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R1],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R2],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R3]
  };

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32x pw_r_len = pwlenx_create_combt (combs_buf, il_pos) & 63;

    const u32x pw_len = (pw_l_len + pw_r_len) & 63;

    /**
     * concat password candidate
     */

    u32x wordl0[4] = { 0 };
    u32x wordl1[4] = { 0 };
    u32x wordl2[4] = { 0 };
    u32x wordl3[4] = { 0 };

    wordl0[0] = pw_buf0[0];
    wordl0[1] = pw_buf0[1];
    wordl0[2] = pw_buf0[2];
    wordl0[3] = pw_buf0[3];
    wordl1[0] = pw_buf1[0];
    wordl1[1] = pw_buf1[1];
    wordl1[2] = pw_buf1[2];
    wordl1[3] = pw_buf1[3];

    u32x wordr0[4] = { 0 };
    u32x wordr1[4] = { 0 };
    u32x wordr2[4] = { 0 };
    u32x wordr3[4] = { 0 };

    wordr0[0] = ix_create_combt (combs_buf, il_pos, 0);
    wordr0[1] = ix_create_combt (combs_buf, il_pos, 1);
    wordr0[2] = ix_create_combt (combs_buf, il_pos, 2);
    wordr0[3] = ix_create_combt (combs_buf, il_pos, 3);
    wordr1[0] = ix_create_combt (combs_buf, il_pos, 4);
    wordr1[1] = ix_create_combt (combs_buf, il_pos, 5);
    wordr1[2] = ix_create_combt (combs_buf, il_pos, 6);
    wordr1[3] = ix_create_combt (combs_buf, il_pos, 7);

    if (COMBS_MODE == COMBINATOR_MODE_BASE_LEFT)
    {
      switch_buffer_by_offset_le_VV (wordr0, wordr1, wordr2, wordr3, pw_l_len);
    }
    else
    {
      switch_buffer_by_offset_le_VV (wordl0, wordl1, wordl2, wordl3, pw_r_len);
    }

    u32x w0[4];
    u32x w1[4];
    u32x w2[4];
    u32x w3[4];

    w0[0] = wordl0[0] | wordr0[0];
    w0[1] = wordl0[1] | wordr0[1];
    w0[2] = wordl0[2] | wordr0[2];
    w0[3] = wordl0[3] | wordr0[3];
    w1[0] = wordl1[0] | wordr1[0];
    w1[1] = wordl1[1] | wordr1[1];
    w1[2] = wordl1[2] | wordr1[2];
    w1[3] = wordl1[3] | wordr1[3];
    w2[0] = wordl2[0] | wordr2[0];
    w2[1] = wordl2[1] | wordr2[1];
    w2[2] = wordl2[2] | wordr2[2];
    w2[3] = wordl2[3] | wordr2[3];
    w3[0] = wordl3[0] | wordr3[0];
    w3[1] = wordl3[1] | wordr3[1];
    w3[2] = pw_len * 8;
    w3[3] = 0;

    /**
     * prepend salt2
     */

    switch_buffer_by_offset_le (w0, w1, w2, w3, salt2_len);

    const u32x pw_salt_len = pw_len + salt2_len;

    w0[0] |= salt2_buf0[0];
    w0[1] |= salt2_buf0[1];
    w0[2] |= salt2_buf0[2];
    w0[3] |= salt2_buf0[3];
    w1[0] |= salt2_buf1[0];
    w1[1] |= salt2_buf1[1];
    w1[2] |= salt2_buf1[2];
    w1[3] |= salt2_buf1[3];
    w2[0] |= salt2_buf2[0];
    w2[1] |= salt2_buf2[1];
    w2[2] |= salt2_buf2[2];
    w2[3] |= salt2_buf2[3];
    w3[0] |= salt2_buf3[0];
    w3[1] |= salt2_buf3[1];
    w3[2]  = pw_salt_len * 8;
    w3[3]  = 0;

    /**
     * md5
     */

    u32x a = MD5M_A;
    u32x b = MD5M_B;
    u32x c = MD5M_C;
    u32x d = MD5M_D;

    MD5_STEP (MD5_Fo, a, b, c, d, w0[0], MD5C00, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w0[1], MD5C01, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w0[2], MD5C02, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w0[3], MD5C03, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, w1[0], MD5C04, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w1[1], MD5C05, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w1[2], MD5C06, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w1[3], MD5C07, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, w2[0], MD5C08, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w2[1], MD5C09, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w2[2], MD5C0a, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w2[3], MD5C0b, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, w3[0], MD5C0c, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w3[1], MD5C0d, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w3[2], MD5C0e, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w3[3], MD5C0f, MD5S03);

    MD5_STEP (MD5_Go, a, b, c, d, w0[1], MD5C10, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w1[2], MD5C11, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w2[3], MD5C12, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w0[0], MD5C13, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, w1[1], MD5C14, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w2[2], MD5C15, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w3[3], MD5C16, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w1[0], MD5C17, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, w2[1], MD5C18, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w3[2], MD5C19, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w0[3], MD5C1a, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w2[0], MD5C1b, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, w3[1], MD5C1c, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w0[2], MD5C1d, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w1[3], MD5C1e, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w3[0], MD5C1f, MD5S13);

    u32x t;

    MD5_STEP (MD5_H1, a, b, c, d, w1[1], MD5C20, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, w2[0], MD5C21, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, w2[3], MD5C22, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, w3[2], MD5C23, MD5S23);
    MD5_STEP (MD5_H1, a, b, c, d, w0[1], MD5C24, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, w1[0], MD5C25, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, w1[3], MD5C26, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, w2[2], MD5C27, MD5S23);
    MD5_STEP (MD5_H1, a, b, c, d, w3[1], MD5C28, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, w0[0], MD5C29, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, w0[3], MD5C2a, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, w1[2], MD5C2b, MD5S23);
    MD5_STEP (MD5_H1, a, b, c, d, w2[1], MD5C2c, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, w3[0], MD5C2d, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, w3[3], MD5C2e, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, w0[2], MD5C2f, MD5S23);

    MD5_STEP (MD5_I , a, b, c, d, w0[0], MD5C30, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w1[3], MD5C31, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w3[2], MD5C32, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w1[1], MD5C33, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, w3[0], MD5C34, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w0[3], MD5C35, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w2[2], MD5C36, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w0[1], MD5C37, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, w2[0], MD5C38, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w3[3], MD5C39, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w1[2], MD5C3a, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w3[1], MD5C3b, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, w1[0], MD5C3c, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w2[3], MD5C3d, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w0[2], MD5C3e, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w2[1], MD5C3f, MD5S33);

    a += make_u32x (MD5M_A);
    b += make_u32x (MD5M_B);
    c += make_u32x (MD5M_C);
    d += make_u32x (MD5M_D);

    w0[0] = uint_to_hex_upper8 ((a >>  0) & 255) <<  0
          | uint_to_hex_upper8 ((a >>  8) & 255) << 16;
    w0[1] = uint_to_hex_upper8 ((a >> 16) & 255) <<  0
          | uint_to_hex_upper8 ((a >> 24) & 255) << 16;
    w0[2] = uint_to_hex_upper8 ((b >>  0) & 255) <<  0
          | uint_to_hex_upper8 ((b >>  8) & 255) << 16;
    w0[3] = uint_to_hex_upper8 ((b >> 16) & 255) <<  0
          | uint_to_hex_upper8 ((b >> 24) & 255) << 16;
    w1[0] = uint_to_hex_upper8 ((c >>  0) & 255) <<  0
          | uint_to_hex_upper8 ((c >>  8) & 255) << 16;
    w1[1] = uint_to_hex_upper8 ((c >> 16) & 255) <<  0
          | uint_to_hex_upper8 ((c >> 24) & 255) << 16;
    w1[2] = uint_to_hex_upper8 ((d >>  0) & 255) <<  0
          | uint_to_hex_upper8 ((d >>  8) & 255) << 16;
    w1[3] = uint_to_hex_upper8 ((d >> 16) & 255) <<  0
          | uint_to_hex_upper8 ((d >> 24) & 255) << 16;
    w2[0] = 0x80;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 0;

    /**
     * prepend salt1
     */

    switch_buffer_by_offset_le (w0, w1, w2, w3, salt1_len);

    w3[2] = final_len * 8;
    w3[3] = 0;

    w0[0] |= salt1_buf0[0];
    w0[1] |= salt1_buf0[1];
    w0[2] |= salt1_buf0[2];
    w0[3] |= salt1_buf0[3];
    w1[0] |= salt1_buf1[0];
    w1[1] |= salt1_buf1[1];
    w1[2] |= salt1_buf1[2];
    w1[3] |= salt1_buf1[3];
    w2[0] |= salt1_buf2[0];
    w2[1] |= salt1_buf2[1];
    w2[2] |= salt1_buf2[2];
    w2[3] |= salt1_buf2[3];
    w3[0] |= salt1_buf3[0];
    w3[1] |= salt1_buf3[1];
    w3[2] |= salt1_buf3[2];
    w3[3] |= salt1_buf3[3];

    /**
     * md5
     */

    a = MD5M_A;
    b = MD5M_B;
    c = MD5M_C;
    d = MD5M_D;

    MD5_STEP (MD5_Fo, a, b, c, d, w0[0], MD5C00, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w0[1], MD5C01, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w0[2], MD5C02, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w0[3], MD5C03, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, w1[0], MD5C04, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w1[1], MD5C05, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w1[2], MD5C06, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w1[3], MD5C07, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, w2[0], MD5C08, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w2[1], MD5C09, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w2[2], MD5C0a, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w2[3], MD5C0b, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, w3[0], MD5C0c, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w3[1], MD5C0d, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w3[2], MD5C0e, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w3[3], MD5C0f, MD5S03);

    MD5_STEP (MD5_Go, a, b, c, d, w0[1], MD5C10, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w1[2], MD5C11, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w2[3], MD5C12, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w0[0], MD5C13, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, w1[1], MD5C14, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w2[2], MD5C15, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w3[3], MD5C16, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w1[0], MD5C17, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, w2[1], MD5C18, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w3[2], MD5C19, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w0[3], MD5C1a, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w2[0], MD5C1b, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, w3[1], MD5C1c, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w0[2], MD5C1d, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w1[3], MD5C1e, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w3[0], MD5C1f, MD5S13);

    MD5_STEP (MD5_H1, a, b, c, d, w1[1], MD5C20, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, w2[0], MD5C21, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, w2[3], MD5C22, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, w3[2], MD5C23, MD5S23);
    MD5_STEP (MD5_H1, a, b, c, d, w0[1], MD5C24, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, w1[0], MD5C25, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, w1[3], MD5C26, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, w2[2], MD5C27, MD5S23);
    MD5_STEP (MD5_H1, a, b, c, d, w3[1], MD5C28, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, w0[0], MD5C29, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, w0[3], MD5C2a, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, w1[2], MD5C2b, MD5S23);
    MD5_STEP (MD5_H1, a, b, c, d, w2[1], MD5C2c, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, w3[0], MD5C2d, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, w3[3], MD5C2e, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, w0[2], MD5C2f, MD5S23);

    MD5_STEP (MD5_I , a, b, c, d, w0[0], MD5C30, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w1[3], MD5C31, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w3[2], MD5C32, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w1[1], MD5C33, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, w3[0], MD5C34, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w0[3], MD5C35, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w2[2], MD5C36, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w0[1], MD5C37, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, w2[0], MD5C38, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w3[3], MD5C39, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w1[2], MD5C3a, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w3[1], MD5C3b, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, w1[0], MD5C3c, MD5S30);

    if (MATCHES_NONE_VS (a, search[0])) continue;

    MD5_STEP (MD5_I , d, a, b, c, w2[3], MD5C3d, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w0[2], MD5C3e, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w2[1], MD5C3f, MD5S33);

    COMPARE_S_SIMD (a, d, c, b);
  }
}

KERNEL_FQ void m03730_s08 (KERN_ATTR_BASIC_ESALT (md5_double_salt_t))
{
}

KERNEL_FQ void m03730_s16 (KERN_ATTR_BASIC_ESALT (md5_double_salt_t))
{
}
