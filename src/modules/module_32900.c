/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "modules.h"
#include "bitops.h"
#include "convert.h"
#include "shared.h"
#include "event.h"

static const u32 ATTACK_EXEC = ATTACK_EXEC_OUTSIDE_KERNEL;
static const u32 DGST_POS0 = 0;
static const u32 DGST_POS1 = 1;
static const u32 DGST_POS2 = 2;
static const u32 DGST_POS3 = 3;
static const u32 DGST_SIZE = DGST_SIZE_4_4;
static const u32 HASH_CATEGORY = HASH_CATEGORY_NETWORK_PROTOCOL;
static const char *HASH_NAME = "Kerberos 5, etype 18, AS-REP (ticket)";
static const u64 KERN_TYPE = 32900;
static const u32 OPTI_TYPE = OPTI_TYPE_ZERO_BYTE | OPTI_TYPE_NOT_ITERATED | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
static const u64 OPTS_TYPE = OPTS_TYPE_STOCK_MODULE | OPTS_TYPE_PT_GENERATE_LE;
static const u32 SALT_TYPE = SALT_TYPE_EMBEDDED;
static const char *ST_PASS = "hashcat";
static const char *ST_HASH = "$krb5tgt$18$admin$5128473e5950775f59255d2c644c4741$943bcf494a45ce142d2622a0$4c1b2f62073834249b1fb6ce74f6b5a333b6f26f84df1d731bc070975f39fd04d5fac0de8e78df8025995db2f7773ca0e846fdc73a8e143a7b801fc7b1f0093e29af14e859ef8f613a87f8027f4efeba2efc329d547444609a50b0a908c8cbd84e9738e7b9a8996ec94aafcd4a534ef2a561fe0513d4524b70513db1a9b632791b3240bc5bb675e8e360721d4807078f68c336a26207a67f20e21000fea3528a917f1d456615aeb1bb2cab92a88e2e3b4b32968252d3244baddfbcf646dee7e09591a1e0086d0500774177637f8e1c24b506d39edada0b278fe90f4db5b7a11d98d4912ae73b6c8b668489bcc73f6855fa8c78a442ef50c5d92fa9038901b2502923da78190848c0514cd6667bdd66f6397e2920e42a7a28cbdecc3e3ea9bc0dd21e461141c16c192e036c74604a23a38bad46a8e48d42a068d9ab79bd09a86f80cf2f07466cdccc0bea2e8137eed25ebeb6011c1d6487b516af5515be1d8fa0b318e9a1b58edb741792df782bdeb79b94b5722e90cf31497dd39bd308085913024415629f2f3ed3bcc80d7c017663b7d8bdae35193e27bcae115be24655e54089688a70f4f9eeb70185799564d69ff3a70d18106612e0100d2b4cb68d0c5baafe882a0f6824a78325e129344d37b4ef0d689bada619bce04eb14453d7fa0aefdcb1956a6aa8cb4724f4029c9e165dadefbfdb87aee6318f01716367a440bdf32b386b5f2ffe521654a42bdd232f07e3a050335167ded9382b9fe2139a3e151b5a742cc6ba69f4fd6393b252bdbae9ce8e76a469cd22693372eab32aa2bb85467c634dd05d788701ba098101c998a5983caed718c6a511f87d9a52ba58bfa034bb1c71e3677d0da3b44753dc8fe662d760b0d745762e46832f4eea868f7d122d7ed68ddb34cc5e3f667030a3c96f4a7485872347a23864d5f6ec081de9cfedfc699ad312fdf654a77d8350eccc921e75d7404192867fbef892fb7d1a24929f4fb93ff8fcb31637d0a3ade9407499f5f12998e53e41e103a6f0081625b654351f76274d65f09ffe530b597f02f188d840d3b9409dde532e655c0e3a58c1271b45a5a1e70083a0ca893ab0b4a768e63ddddde17bd077d0cf9b6a0fb98924549fc12ba890703760b9ee05c68807e07010aa3b3590965f41e28dfe0c2ae18d7cb3398faa08b2072cbb35db738171ebe50b7f224ec6483f7a2231723a08747151bdedb173e877eea30d899c5698d64b26217d2d346fbbd635b339deeec8cf396b656284cd313c0e9c71594486d18df29c6c52f3f77103bc9248ae043bbaa2976a48d8ccf0f4c63285c9cb880886350bd0f89f4cbc859a32e673d602dccf05969dfb1f6e8548a01857794ba8af8c713a917132d509b2275f181b933ef182e676a8ae2dbbdcb5744eb6d622f0c9fd8db84372fc8f13616da4fbd5d6ceafd80b5832d33643c73b72372a1b74076c7305b9da485e25eabbe55d479da93e5d259bd38f169458827d3fecb535d6190d";

u32 module_attack_exec(MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return ATTACK_EXEC; }
u32 module_dgst_pos0(MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS0; }
u32 module_dgst_pos1(MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS1; }
u32 module_dgst_pos2(MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS2; }
u32 module_dgst_pos3(MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS3; }
u32 module_dgst_size(MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_SIZE; }
u32 module_hash_category(MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_CATEGORY; }
const char *module_hash_name(MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_NAME; }
u64 module_kern_type(MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return KERN_TYPE; }
u32 module_opti_type(MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return OPTI_TYPE; }
u64 module_opts_type(MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return OPTS_TYPE; }
u32 module_salt_type(MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return SALT_TYPE; }
const char *module_st_hash(MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return ST_HASH; }
const char *module_st_pass(MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return ST_PASS; }

typedef struct krb5tgt_18
{
    u32 user[128];
    u32 salt[512];
    u32 salt_len;
    u32 checksum[3]; // 12 bytes macsize for AES256-SHA1
    u32 ticket[5120];
    u32 ticket_len;
} krb5tgt_18_t;

typedef struct krb5tgt_18_tmp
{
    u32 ipad[5];
    u32 opad[5];
    u32 dgst[16];
    u32 out[16];

} krb5tgt_18_tmp_t;

static const char *SIGNATURE_KRB5TGT_TICKET = "$krb5tgt$18$";

u64 module_tmp_size(MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
    const u64 tmp_size = (const u64)sizeof(krb5tgt_18_tmp_t);

    return tmp_size;
}

u64 module_esalt_size(MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
    const u64 esalt_size = (const u64)sizeof(krb5tgt_18_t);

    return esalt_size;
}

int module_hash_decode(MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
    u32 *digest = (u32 *)digest_buf;

    krb5tgt_18_t *krb5tgt = (krb5tgt_18_t *)esalt_buf;

    hc_token_t token;
    memset(&token, 0, sizeof(hc_token_t));

    // $krb5tgt$18$user$salt$checksum$ticket
    token.signatures_cnt = 1;
    token.signatures_buf[0] = SIGNATURE_KRB5TGT_TICKET;

    token.len[0] = strlen(SIGNATURE_KRB5TGT_TICKET);
    token.attr[0] = TOKEN_ATTR_FIXED_LENGTH | TOKEN_ATTR_VERIFY_SIGNATURE;

    // assume no signature found
    if (line_len < (int)strlen(SIGNATURE_KRB5TGT_TICKET))
        return (PARSER_SALT_LENGTH);

    token.token_cnt = 5;
    // user
    token.sep[1] = '$';
    token.len_min[1] = 1;
    token.len_max[1] = 512;
    token.attr[1] = TOKEN_ATTR_VERIFY_LENGTH;
    // salt
    token.sep[2] = '$';
    token.len_min[2] = 1;
    token.len_max[2] = 512;
    token.attr[2] = TOKEN_ATTR_VERIFY_LENGTH | TOKEN_ATTR_VERIFY_HEX;
    // checksum
    token.sep[3] = '$';
    token.len[3] = 24; // 12 bytes macsize * 2 (as it in hex)
    token.attr[3] = TOKEN_ATTR_FIXED_LENGTH | TOKEN_ATTR_VERIFY_HEX;
    // ticket
    token.sep[4] = '$';
    token.len_min[4] = 64;
    token.len_max[4] = 40960;
    token.attr[4] = TOKEN_ATTR_VERIFY_LENGTH | TOKEN_ATTR_VERIFY_HEX;

    const int rc_tokenizer = input_tokenizer((const u8 *)line_buf, line_len, &token);

    if (rc_tokenizer != PARSER_OK)
        return (rc_tokenizer);

    // user
    const u8 *user_pos;
    int user_len;
    user_pos = token.buf[1];
    user_len = token.len[1];
    memcpy(krb5tgt->user, user_pos, user_len);

    // salt
    const u8 *salt_pos;
    int salt_len;
    salt_pos = token.buf[2];
    salt_len = token.len[2];

    // checksum
    const u8 *checksum_pos;
    checksum_pos = token.buf[3];

    // ticket
    const u8 *ticket_pos;
    int ticket_len;
    ticket_pos = token.buf[4];
    ticket_len = token.len[4];

    // hmac-sha1 is reduced to 12 bytes
    krb5tgt->checksum[0] = byte_swap_32(hex_to_u32(checksum_pos + 0));
    krb5tgt->checksum[1] = byte_swap_32(hex_to_u32(checksum_pos + 8));
    krb5tgt->checksum[2] = byte_swap_32(hex_to_u32(checksum_pos + 16));
    
    // unhexify salt
    u8 *salt_ptr = (u8 *)krb5tgt->salt;
    for (int i = 0; i < salt_len; i += 2)
    {
        const u8 p0 = salt_pos[i + 0];
        const u8 p1 = salt_pos[i + 1];
        *salt_ptr++ = hex_convert(p1) << 0 | hex_convert(p0) << 4;
    }
    // set length of salt
    krb5tgt->salt_len = salt_len / 2;

    // unhexify ticket
    u8 *ticket_ptr = (u8 *)krb5tgt->ticket;
    for (int i = 0; i < ticket_len; i += 2)
    {
        const u8 p0 = ticket_pos[i + 0];
        const u8 p1 = ticket_pos[i + 1];
        *ticket_ptr++ = hex_convert(p1) << 0 | hex_convert(p0) << 4;
    }
    // set length of ticket
    krb5tgt->ticket_len = ticket_len / 2;

    salt->salt_buf[0] = krb5tgt->checksum[0];
    salt->salt_buf[1] = krb5tgt->checksum[1];
    salt->salt_buf[2] = krb5tgt->checksum[2];
    salt->salt_len = 12;
    salt->salt_iter = 4095;

    digest[0] = krb5tgt->checksum[0];
    digest[1] = krb5tgt->checksum[1];
    digest[2] = krb5tgt->checksum[2];
    digest[3] = 0;
    return (PARSER_OK);
}

int module_hash_encode(MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
    const krb5tgt_18_t *krb5tgt = (const krb5tgt_18_t *)esalt_buf;

    // hexify salt
    char salt_hex[128 * 4 * 2] = {0};
    for (u32 i = 0, j = 0; i < krb5tgt->salt_len; i += 1, j += 2)
    {
        const u8 *ptr_salt = (const u8 *)krb5tgt->salt;
        snprintf(salt_hex + j, 3, "%02x", ptr_salt[i]);
    }

    // hexify ticket
    char ticket_hex[5120 * 4 * 2] = {0};
    for (u32 i = 0, j = 0; i < krb5tgt->ticket_len; i += 1, j += 2)
    {
        const u8 *ptr_ticket = (const u8 *)krb5tgt->ticket;

        snprintf(ticket_hex + j, 3, "%02x", ptr_ticket[i]);
    }

    const int line_len = snprintf(line_buf, line_size, "%s%s$%s$%08x%08x%08x$%s",
                                  SIGNATURE_KRB5TGT_TICKET,
                                  (const char *)krb5tgt->user,
                                  salt_hex,
                                  krb5tgt->checksum[0],
                                  krb5tgt->checksum[1],
                                  krb5tgt->checksum[2],
                                  ticket_hex);

    return line_len;
}

void module_init(module_ctx_t *module_ctx)
{
    module_ctx->module_context_size = MODULE_CONTEXT_SIZE_CURRENT;
    module_ctx->module_interface_version = MODULE_INTERFACE_VERSION_CURRENT;

    module_ctx->module_attack_exec = module_attack_exec;
    module_ctx->module_benchmark_esalt = MODULE_DEFAULT;
    module_ctx->module_benchmark_hook_salt = MODULE_DEFAULT;
    module_ctx->module_benchmark_mask = MODULE_DEFAULT;
    module_ctx->module_benchmark_charset = MODULE_DEFAULT;
    module_ctx->module_benchmark_salt = MODULE_DEFAULT;
    module_ctx->module_build_plain_postprocess = MODULE_DEFAULT;
    module_ctx->module_deep_comp_kernel = MODULE_DEFAULT;
    module_ctx->module_deprecated_notice = MODULE_DEFAULT;
    module_ctx->module_dgst_pos0 = module_dgst_pos0;
    module_ctx->module_dgst_pos1 = module_dgst_pos1;
    module_ctx->module_dgst_pos2 = module_dgst_pos2;
    module_ctx->module_dgst_pos3 = module_dgst_pos3;
    module_ctx->module_dgst_size = module_dgst_size;
    module_ctx->module_dictstat_disable = MODULE_DEFAULT;
    module_ctx->module_esalt_size = module_esalt_size;
    module_ctx->module_extra_buffer_size = MODULE_DEFAULT;
    module_ctx->module_extra_tmp_size = MODULE_DEFAULT;
    module_ctx->module_extra_tuningdb_block = MODULE_DEFAULT;
    module_ctx->module_forced_outfile_format = MODULE_DEFAULT;
    module_ctx->module_hash_binary_count = MODULE_DEFAULT;
    module_ctx->module_hash_binary_parse = MODULE_DEFAULT;
    module_ctx->module_hash_binary_save = MODULE_DEFAULT;
    module_ctx->module_hash_decode_postprocess = MODULE_DEFAULT;
    module_ctx->module_hash_decode_potfile = MODULE_DEFAULT;
    module_ctx->module_hash_decode_zero_hash = MODULE_DEFAULT;
    module_ctx->module_hash_decode = module_hash_decode;
    module_ctx->module_hash_encode_status = MODULE_DEFAULT;
    module_ctx->module_hash_encode_potfile = MODULE_DEFAULT;
    module_ctx->module_hash_encode = module_hash_encode;
    module_ctx->module_hash_init_selftest = MODULE_DEFAULT;
    module_ctx->module_hash_mode = MODULE_DEFAULT;
    module_ctx->module_hash_category = module_hash_category;
    module_ctx->module_hash_name = module_hash_name;
    module_ctx->module_hashes_count_min = MODULE_DEFAULT;
    module_ctx->module_hashes_count_max = MODULE_DEFAULT;
    module_ctx->module_hlfmt_disable = MODULE_DEFAULT;
    module_ctx->module_hook_extra_param_size = MODULE_DEFAULT;
    module_ctx->module_hook_extra_param_init = MODULE_DEFAULT;
    module_ctx->module_hook_extra_param_term = MODULE_DEFAULT;
    module_ctx->module_hook12 = MODULE_DEFAULT;
    module_ctx->module_hook23 = MODULE_DEFAULT;
    module_ctx->module_hook_salt_size = MODULE_DEFAULT;
    module_ctx->module_hook_size = MODULE_DEFAULT;
    module_ctx->module_jit_build_options = MODULE_DEFAULT;
    module_ctx->module_jit_cache_disable = MODULE_DEFAULT;
    module_ctx->module_kernel_accel_max = MODULE_DEFAULT;
    module_ctx->module_kernel_accel_min = MODULE_DEFAULT;
    module_ctx->module_kernel_loops_max = MODULE_DEFAULT;
    module_ctx->module_kernel_loops_min = MODULE_DEFAULT;
    module_ctx->module_kernel_threads_max = MODULE_DEFAULT;
    module_ctx->module_kernel_threads_min = MODULE_DEFAULT;
    module_ctx->module_kern_type = module_kern_type;
    module_ctx->module_kern_type_dynamic = MODULE_DEFAULT;
    module_ctx->module_opti_type = module_opti_type;
    module_ctx->module_opts_type = module_opts_type;
    module_ctx->module_outfile_check_disable = MODULE_DEFAULT;
    module_ctx->module_outfile_check_nocomp = MODULE_DEFAULT;
    module_ctx->module_potfile_custom_check = MODULE_DEFAULT;
    module_ctx->module_potfile_disable = MODULE_DEFAULT;
    module_ctx->module_potfile_keep_all_hashes = MODULE_DEFAULT;
    module_ctx->module_pwdump_column = MODULE_DEFAULT;
    module_ctx->module_pw_max = MODULE_DEFAULT;
    module_ctx->module_pw_min = MODULE_DEFAULT;
    module_ctx->module_salt_max = MODULE_DEFAULT;
    module_ctx->module_salt_min = MODULE_DEFAULT;
    module_ctx->module_salt_type = module_salt_type;
    module_ctx->module_separator = MODULE_DEFAULT;
    module_ctx->module_st_hash = module_st_hash;
    module_ctx->module_st_pass = module_st_pass;
    module_ctx->module_tmp_size = module_tmp_size;
    module_ctx->module_unstable_warning = MODULE_DEFAULT;
    module_ctx->module_warmup_disable = MODULE_DEFAULT;
}
