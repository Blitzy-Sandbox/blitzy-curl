/* =========================================================================
 * curl-rs-ffi/csrc/mprintf.c — curl's own printf engine, ported self-contained.
 *
 * Part of the curl -> Rust migration (curl-rs-ffi crate). This translation unit
 * defines the ten exported `curl_m*printf` / `curl_mv*printf` symbols that
 * `include/curl/mprintf.h` declares (the printf family enumerated in
 * `lib/libcurl.def`). It is compiled by `curl-rs-ffi/build.rs` via the `cc`
 * crate and linked into the `libcurl`-compatible cdylib/staticlib with the
 * `+whole-archive` modifier so the symbols are present in the final library's
 * exported symbol table (the `nm` / `objdump` parity gate, AAP §0.7.2).
 *
 * ---------------------------------------------------------------------------
 * WHY C (and not Rust) — documented no-C-mandate exception (AAP §0.8.2/§0.8.3)
 * ---------------------------------------------------------------------------
 * AAP §0.8.2 forbids C linkage against `libcurl` / `libssl` / C TLS libraries
 * and C protocol/TLS backends. This file is NONE of those: it is a tiny,
 * dependency-free formatter that ONLY bridges a calling convention which stable
 * Rust provably cannot express. On stable Rust (MSRV 1.75, edition 2021):
 *
 *   (a) a variadic `extern "C" fn(fmt: *const c_char, ...)` CANNOT be *defined*
 *       — the `c_variadic` feature is nightly-only; and
 *   (b) there is no stable `va_list` type — `core::ffi::VaList` is unstable.
 *
 * The `curl_m*printf` group is C-variadic and the `curl_mv*printf` group takes
 * a `va_list`, so BOTH families hit these limits. A C compiler natively handles
 * both ABIs on every target in the four-target matrix (linux x86_64/aarch64,
 * macOS x86_64/arm64). This file links no third-party C library.
 *
 * ---------------------------------------------------------------------------
 * BEHAVIORAL PARITY (oracle: lib/mprintf.c) — WHY A FULL PORT, NOT libc
 * ---------------------------------------------------------------------------
 * curl ships its OWN printf engine in `lib/mprintf.c` whose semantics differ
 * from the platform C library in ways the regression suite verifies directly
 * (`tests/libtest/lib557.c`):
 *
 *   * Positional arguments are validated by curl, not by glibc: mixing
 *     positional and non-positional conversions (e.g. "%3$d %d %2$d") yields an
 *     EMPTY string, where glibc would format something.
 *   * A hard limit of MAX_PARAMETERS (128) input arguments — the 129th `%d`
 *     makes the whole call produce "" and return 0.
 *   * Width / precision are clamped to BUFFSIZE-1 (325) for doubles, so
 *     "%325.325f", "%326.326f" and "%1000.1000f" all return 325.
 *   * `curl_msnprintf` returns the bytes ACTUALLY stored (capped at
 *     `maxlength-1`), not the would-be length that C99 `vsnprintf` returns.
 *   * Unknown conversions are passed through verbatim ("%K" stays "%K").
 *
 * Forwarding to the platform `v*printf` (the previous implementation here)
 * cannot reproduce these, so this file PORTS curl's engine verbatim — the same
 * `parsefmt` / `formatf` / `out_*` logic and the same public entry points — made
 * self-contained by replacing curl's internal dependencies with small local
 * equivalents:
 *
 *   * `curlx/strparse` (`curlx_str_number` / `curlx_str_single`) -> the local
 *     `tr_str_number` / `tr_str_single` below (a faithful base-10 port,
 *     including the exact digit table and overflow checks).
 *   * `curlx/dynbuf` (the growable buffer behind `curl_maprintf`) -> the local
 *     malloc/realloc-based `tr_growbuf` below.
 *   * `curl_setup.h` macros (`bool`/`TRUE`/`FALSE`, `FALLTHROUGH`,
 *     `DEBUGASSERT`, the `SIZEOF_*` build constants, `Curl_l/udigits`) -> the
 *     local prelude below. The `SIZEOF_*` values come from the compiler's own
 *     `__SIZEOF_*__` predefined macros so the `%z` / `%O` width selection is
 *     correct on any target, with a `_Static_assert` cross-check.
 *
 * ---------------------------------------------------------------------------
 * MEMORY OWNERSHIP (`curl_maprintf` / `curl_mvaprintf`)
 * ---------------------------------------------------------------------------
 * These two return a heap buffer that the CALLER releases with `curl_free`.
 * The crate's `curl_free` (see `curl-rs-ffi/src/global.rs`) wraps `libc::free`,
 * and the buffer here is produced with `malloc`/`realloc` from that same C heap,
 * so the allocate-here / free-there contract is consistent (matching curl's own
 * `curl_maprintf` ownership rule).
 * ========================================================================= */

#include <stdio.h>  /* FILE, snprintf, fputc, stdout, EOF */
#include <stdarg.h> /* va_list, va_start, va_end, va_copy  */
#include <stdlib.h> /* malloc, realloc, free               */
#include <string.h> /* memset, strlen                      */
#include <limits.h> /* INT_MAX, INT_MIN                    */
#include <stdint.h> /* int64_t, uint64_t                   */
#include <stddef.h> /* size_t                              */
#include <stdbool.h>/* bool, true, false                   */

/* --------------------------------------------------------------------------
 * Local prelude — replacements for the `curl_setup.h` macros lib/mprintf.c
 * relies on. Kept file-local so this unit defines no extra global symbols.
 * -------------------------------------------------------------------------- */

#ifndef TRUE
#define TRUE true
#endif
#ifndef FALSE
#define FALSE false
#endif

/* curl's 64-bit file-offset type. Only the format PARSER uses it (parameter
 * numbers, width, precision); the actual %O/%lld arguments are read with the
 * fixed-width int64_t/uint64_t va_arg calls below, so `long long` is exact. */
typedef long long curl_off_t;

/* Build-time size constants used by the %z / %O / %I width selection. The
 * compiler's predefined __SIZEOF_*__ macros are integer constant expressions
 * usable in #if, so the selection stays correct on every target (not just the
 * LP64 four-target matrix). A static assert below cross-checks the typedef. */
#ifdef __SIZEOF_LONG__
#define SIZEOF_LONG __SIZEOF_LONG__
#else
#define SIZEOF_LONG 8
#endif
#ifdef __SIZEOF_SIZE_T__
#define SIZEOF_SIZE_T __SIZEOF_SIZE_T__
#else
#define SIZEOF_SIZE_T 8
#endif
#ifdef __SIZEOF_LONG_LONG__
#define SIZEOF_CURL_OFF_T __SIZEOF_LONG_LONG__
#else
#define SIZEOF_CURL_OFF_T 8
#endif

_Static_assert(sizeof(curl_off_t) == SIZEOF_CURL_OFF_T,
               "curl_off_t width must match SIZEOF_CURL_OFF_T");

/* The platform provides snprintf (C99); enables the double-formatting path. */
#define HAVE_SNPRINTF 1

/* Fall-through marker mirroring curl's FALLTHROUGH(). Used as a null statement
 * (the call sites write `FALLTHROUGH();`). */
#if defined(__GNUC__) && (__GNUC__ >= 7)
#define FALLTHROUGH() __attribute__((fallthrough))
#elif defined(__clang__) && defined(__has_attribute)
#if __has_attribute(fallthrough)
#define FALLTHROUGH() __attribute__((fallthrough))
#else
#define FALLTHROUGH() do {} while(0)
#endif
#else
#define FALLTHROUGH() do {} while(0)
#endif

/* Release-build no-op assert (curl's DEBUGASSERT compiles out in release). */
#define DEBUGASSERT(x) ((void)0)

/* String-parser result codes (subset of curlx/strparse.h used here). */
#define STRE_OK       0
#define STRE_OVERFLOW 7
#define STRE_NO_NUM   8
#define STRE_BYTE     5

/* Lower-case digits (curl's Curl_ldigits, kept file-local). */
static const unsigned char tr_ldigits[] = "0123456789abcdef";
/* Upper-case digits (curl's Curl_udigits, kept file-local). */
static const unsigned char tr_udigits[] = "0123456789ABCDEF";

/* --------------------------------------------------------------------------
 * Local string-number parser — a faithful base-10 port of curlx_str_number /
 * curlx_str_single (lib/curlx/strparse.c), including the exact digit table so
 * the positional/width/precision grammar behaves identically to curl.
 * -------------------------------------------------------------------------- */

/* Index by (c - '0'). Non-zero marks a valid digit; the low nibble is the
 * value. '0' maps to 16 (low nibble 0) so it still tests as "valid". Verbatim
 * from lib/curlx/strparse.c (curlx_hexasciitable). */
static const unsigned char tr_hexasciitable[] = {
  16, 1, 2, 3, 4, 5, 6, 7, 8, 9, /* 0x30: 0 - 9 */
  0, 0, 0, 0, 0, 0, 0,
  10, 11, 12, 13, 14, 15,        /* 0x41: A - F */
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  10, 11, 12, 13, 14, 15         /* 0x61: a - f */
};

#define tr_valid_digit10(x) \
  (((x) >= '0') && ((x) <= '9') && tr_hexasciitable[(unsigned char)(x) - '0'])
#define tr_hexval10(x) \
  (unsigned char)(tr_hexasciitable[(unsigned char)(x) - '0'] & 0x0f)

/* Parse a base-10 number with an inclusive maximum, advancing *linep past the
 * digits. Returns STRE_OK on success (mirrors curlx_str_number with base 10,
 * the only base mprintf uses). */
static int tr_str_number(const char **linep, curl_off_t *nump, curl_off_t max)
{
  curl_off_t num = 0;
  const char *p = *linep;
  const int base = 10;
  *nump = 0;
  if(!tr_valid_digit10(*p))
    return STRE_NO_NUM;
  if(max < base) {
    /* special-case low max: the check needs to be different */
    do {
      int n = tr_hexval10(*p++);
      num = num * base + n;
      if(num > max)
        return STRE_OVERFLOW;
    } while(tr_valid_digit10(*p));
  }
  else {
    do {
      int n = tr_hexval10(*p++);
      if(num > ((max - n) / base))
        return STRE_OVERFLOW;
      num = num * base + n;
    } while(tr_valid_digit10(*p));
  }
  *nump = num;
  *linep = p;
  return STRE_OK;
}

/* Match a single byte and advance past it. Mirrors curlx_str_single. */
static int tr_str_single(const char **linep, char byte)
{
  if(**linep != byte)
    return STRE_BYTE;
  (*linep)++; /* move over it */
  return STRE_OK;
}

/* ==========================================================================
 * curl's printf engine — ported verbatim from lib/mprintf.c. The only edits
 * are dependency substitutions: Curl_l/udigits -> tr_l/udigits,
 * curlx_str_number/single -> tr_str_number/single, and the dynbuf-backed
 * allocator -> tr_growbuf (see the allocating variants near the end).
 * ========================================================================== */

#define BUFFSIZE 326 /* buffer for long-to-str and float-to-str calcs, should
                        fit negative DBL_MAX (317 letters) */
#define MAX_PARAMETERS 128 /* number of input arguments */
#define MAX_SEGMENTS   128 /* number of output segments */

#define OUTCHAR(x)                                       \
  do {                                                   \
    if(stream((unsigned char)(x), userp))                \
      return TRUE;                                       \
    (*donep)++;                                          \
  } while(0)

/* Data type to read from the arglist */
typedef enum {
  MTYPE_STRING,
  MTYPE_PTR,
  MTYPE_INTPTR,
  MTYPE_INT,
  MTYPE_LONG,
  MTYPE_LONGLONG,
  MTYPE_INTU,
  MTYPE_LONGU,
  MTYPE_LONGLONGU,
  MTYPE_DOUBLE,
  MTYPE_LONGDOUBLE,
  MTYPE_WIDTH,
  MTYPE_PRECISION
} FormatType;

/* conversion and display flags */
enum {
  FLAGS_SPACE      = 1 << 0,
  FLAGS_SHOWSIGN   = 1 << 1,
  FLAGS_LEFT       = 1 << 2,
  FLAGS_ALT        = 1 << 3,
  FLAGS_SHORT      = 1 << 4,
  FLAGS_LONG       = 1 << 5,
  FLAGS_LONGLONG   = 1 << 6,
  FLAGS_LONGDOUBLE = 1 << 7,
  FLAGS_PAD_NIL    = 1 << 8,
  FLAGS_UNSIGNED   = 1 << 9,
  FLAGS_OCTAL      = 1 << 10,
  FLAGS_HEX        = 1 << 11,
  FLAGS_UPPER      = 1 << 12,
  FLAGS_WIDTH      = 1 << 13, /* '*' or '*<num>$' used */
  FLAGS_WIDTHPARAM = 1 << 14, /* width PARAMETER was specified */
  FLAGS_PREC       = 1 << 15, /* precision was specified */
  FLAGS_PRECPARAM  = 1 << 16, /* precision PARAMETER was specified */
  FLAGS_CHAR       = 1 << 17, /* %c story */
  FLAGS_FLOATE     = 1 << 18, /* %e or %E */
  FLAGS_FLOATG     = 1 << 19, /* %g or %G */
  FLAGS_SUBSTR     = 1 << 20  /* no input, only substring */
};

enum {
  DOLLAR_UNKNOWN,
  DOLLAR_NOPE,
  DOLLAR_USE
};

/*
 * Describes an input va_arg type and hold its value.
 */
struct va_input {
  FormatType type; /* FormatType */
  union {
    const char *str;
    void *ptr;
    int64_t nums; /* signed */
    uint64_t numu; /* unsigned */
    double dnum;
  } val;
};

/*
 * Describes an output segment.
 */
struct outsegment {
  int width;     /* width OR width parameter number */
  int precision; /* precision OR precision parameter number */
  unsigned int flags;
  unsigned int input; /* input argument array index */
  const char *start; /* format string start to output */
  size_t outlen;     /* number of bytes from the format string to output */
};

struct nsprintf {
  char *buffer;
  size_t length;
  size_t max;
};

/* Public prototypes (declared here so out_double can recurse into
 * curl_msnprintf, which is defined further down). */
int curl_mvsnprintf(char *buffer, size_t maxlength, const char *format,
                    va_list args);
int curl_msnprintf(char *buffer, size_t maxlength, const char *format, ...);
int curl_msprintf(char *buffer, const char *format, ...);
int curl_mprintf(const char *format, ...);
int curl_mfprintf(FILE *fd, const char *format, ...);
char *curl_maprintf(const char *format, ...);
char *curl_mvaprintf(const char *format, va_list args);
int curl_mvsprintf(char *buffer, const char *format, va_list args);
int curl_mvprintf(const char *format, va_list args);
int curl_mvfprintf(FILE *fd, const char *format, va_list args);

/* the provided input number is 1-based but this returns the number 0-based.

   returns -1 if no valid number was provided.
*/
static int dollarstring(const char *p, const char **end)
{
  curl_off_t num;
  if(tr_str_number(&p, &num, MAX_PARAMETERS) ||
     tr_str_single(&p, '$') || !num)
    return -1;
  *end = p;
  return (int)num - 1;
}

#define is_arg_used(x, y)   ((x)[(y) / 8] & (1 << ((y) & 7)))
#define mark_arg_used(x, y) ((x)[(y) / 8] |= (unsigned char)(1 << ((y) & 7)))

/*
 * Parse the format string.
 *
 * Create two arrays. One describes the inputs, one describes the outputs.
 *
 * Returns zero on success.
 */

#define PFMT_OK          0
#define PFMT_DOLLAR      1 /* bad dollar for main param */
#define PFMT_DOLLARWIDTH 2 /* bad dollar use for width */
#define PFMT_DOLLARPREC  3 /* bad dollar use for precision */
#define PFMT_MANYARGS    4 /* too many input arguments used */
#define PFMT_PREC        5 /* precision overflow */
#define PFMT_PRECMIX     6 /* bad mix of precision specifiers */
#define PFMT_WIDTH       7 /* width overflow */
#define PFMT_INPUTGAP    8 /* gap in arguments */
#define PFMT_WIDTHARG    9 /* attempted to use same arg twice, for width */
#define PFMT_PRECARG    10 /* attempted to use same arg twice, for prec */
#define PFMT_MANYSEGS   11 /* maxed out output segments */

static int parsefmt(const char *format,
                    struct outsegment *out,
                    struct va_input *in,
                    int *opieces,
                    int *ipieces, va_list arglist)
{
  const char *fmt = format;
  int param_num = 0;
  int max_param = -1;
  int i;
  int ocount = 0;
  unsigned char usedinput[MAX_PARAMETERS / 8];
  size_t outlen = 0;
  struct outsegment *optr;
  int use_dollar = DOLLAR_UNKNOWN;
  const char *start = fmt;

  /* clear, set a bit for each used input */
  memset(usedinput, 0, sizeof(usedinput));

  while(*fmt) {
    if(*fmt == '%') {
      struct va_input *iptr;
      bool loopit = TRUE;
      FormatType type;
      unsigned int flags = 0;
      int width = 0;
      int precision = 0;
      int param = -1;
      fmt++;
      outlen = (size_t)(fmt - start - 1);
      if(*fmt == '%') {
        /* this means a %% that should be output only as %. Create an output
           segment. */
        if(outlen) {
          optr = &out[ocount++];
          if(ocount > MAX_SEGMENTS)
            return PFMT_MANYSEGS;
          optr->input = 0;
          optr->flags = FLAGS_SUBSTR;
          optr->start = start;
          optr->outlen = outlen;
        }
        start = fmt;
        fmt++;
        continue; /* while */
      }

      if(use_dollar != DOLLAR_NOPE) {
        param = dollarstring(fmt, &fmt);
        if(param < 0) {
          if(use_dollar == DOLLAR_USE)
            /* illegal combo */
            return PFMT_DOLLAR;

          /* we got no positional, just get the next arg */
          param = -1;
          use_dollar = DOLLAR_NOPE;
        }
        else
          use_dollar = DOLLAR_USE;
      }

      /* Handle the flags */
      while(loopit) {
        switch(*fmt++) {
        case ' ':
          flags |= FLAGS_SPACE;
          break;
        case '+':
          flags |= FLAGS_SHOWSIGN;
          break;
        case '-':
          flags |= FLAGS_LEFT;
          flags &= ~(unsigned int)FLAGS_PAD_NIL;
          break;
        case '#':
          flags |= FLAGS_ALT;
          break;
        case '.':
          if('*' == *fmt) {
            /* The precision is picked from a specified parameter */
            flags |= FLAGS_PRECPARAM;
            fmt++;

            if(use_dollar == DOLLAR_USE) {
              precision = dollarstring(fmt, &fmt);
              if(precision < 0)
                /* illegal combo */
                return PFMT_DOLLARPREC;
            }
            else
              /* get it from the next argument */
              precision = -1;
          }
          else {
            bool is_neg;
            curl_off_t num;
            flags |= FLAGS_PREC;
            is_neg = ('-' == *fmt);
            if(is_neg)
              fmt++;
            if(tr_str_number(&fmt, &num, INT_MAX))
              return PFMT_PREC;
            precision = (int)num;
            if(is_neg)
              precision = -precision;
          }
          if((flags & (FLAGS_PREC | FLAGS_PRECPARAM)) ==
             (FLAGS_PREC | FLAGS_PRECPARAM))
            /* it is not permitted to use both kinds of precision for the same
               argument */
            return PFMT_PRECMIX;
          break;
        case 'h':
          flags |= FLAGS_SHORT;
          break;
#ifdef _WIN32
        case 'I':
          /* Non-ANSI integer extensions I32 I64 */
          if((fmt[0] == '3') && (fmt[1] == '2')) {
            flags |= FLAGS_LONG;
            fmt += 2;
          }
          else if((fmt[0] == '6') && (fmt[1] == '4')) {
            flags |= FLAGS_LONGLONG;
            fmt += 2;
          }
          else {
#if (SIZEOF_CURL_OFF_T > SIZEOF_LONG)
            flags |= FLAGS_LONGLONG;
#else
            flags |= FLAGS_LONG;
#endif
          }
          break;
#endif /* _WIN32 */
        case 'l':
          if(flags & FLAGS_LONG)
            flags |= FLAGS_LONGLONG;
          else
            flags |= FLAGS_LONG;
          break;
        case 'L':
          flags |= FLAGS_LONGDOUBLE;
          break;
        case 'q':
          flags |= FLAGS_LONGLONG;
          break;
        case 'z':
          /* the code below generates a warning if -Wunreachable-code is
             used */
#if (SIZEOF_SIZE_T > SIZEOF_LONG)
          flags |= FLAGS_LONGLONG;
#else
          flags |= FLAGS_LONG;
#endif
          break;
        case 'O':
#if (SIZEOF_CURL_OFF_T > SIZEOF_LONG)
          flags |= FLAGS_LONGLONG;
#else
          flags |= FLAGS_LONG;
#endif
          break;
        case '0':
          if(!(flags & FLAGS_LEFT))
            flags |= FLAGS_PAD_NIL;
          FALLTHROUGH();
        case '1':
        case '2':
        case '3':
        case '4':
        case '5':
        case '6':
        case '7':
        case '8':
        case '9': {
          curl_off_t num;
          flags |= FLAGS_WIDTH;
          fmt--;
          if(tr_str_number(&fmt, &num, INT_MAX))
            return PFMT_WIDTH;
          width = (int)num;
          break;
        }
        case '*':  /* read width from argument list */
          flags |= FLAGS_WIDTHPARAM;
          if(use_dollar == DOLLAR_USE) {
            width = dollarstring(fmt, &fmt);
            if(width < 0)
              /* illegal combo */
              return PFMT_DOLLARWIDTH;
          }
          else
            /* pick from the next argument */
            width = -1;
          break;
        default:
          loopit = FALSE;
          fmt--;
          break;
        } /* switch */
      } /* while */

      switch(*fmt) {
      case 'S':
        flags |= FLAGS_ALT;
        FALLTHROUGH();
      case 's':
        type = MTYPE_STRING;
        break;
      case 'n':
        type = MTYPE_INTPTR;
        break;
      case 'p':
        type = MTYPE_PTR;
        break;
      case 'd':
      case 'i':
        if(flags & FLAGS_LONGLONG)
          type = MTYPE_LONGLONG;
        else if(flags & FLAGS_LONG)
          type = MTYPE_LONG;
        else
          type = MTYPE_INT;
        break;
      case 'u':
        if(flags & FLAGS_LONGLONG)
          type = MTYPE_LONGLONGU;
        else if(flags & FLAGS_LONG)
          type = MTYPE_LONGU;
        else
          type = MTYPE_INTU;
        flags |= FLAGS_UNSIGNED;
        break;
      case 'o':
        if(flags & FLAGS_LONGLONG)
          type = MTYPE_LONGLONGU;
        else if(flags & FLAGS_LONG)
          type = MTYPE_LONGU;
        else
          type = MTYPE_INTU;
        flags |= FLAGS_OCTAL | FLAGS_UNSIGNED;
        break;
      case 'x':
        if(flags & FLAGS_LONGLONG)
          type = MTYPE_LONGLONGU;
        else if(flags & FLAGS_LONG)
          type = MTYPE_LONGU;
        else
          type = MTYPE_INTU;
        flags |= FLAGS_HEX | FLAGS_UNSIGNED;
        break;
      case 'X':
        if(flags & FLAGS_LONGLONG)
          type = MTYPE_LONGLONGU;
        else if(flags & FLAGS_LONG)
          type = MTYPE_LONGU;
        else
          type = MTYPE_INTU;
        flags |= FLAGS_HEX | FLAGS_UPPER | FLAGS_UNSIGNED;
        break;
      case 'c':
        type = MTYPE_INT;
        flags |= FLAGS_CHAR;
        break;
      case 'f':
        type = MTYPE_DOUBLE;
        break;
      case 'e':
        type = MTYPE_DOUBLE;
        flags |= FLAGS_FLOATE;
        break;
      case 'E':
        type = MTYPE_DOUBLE;
        flags |= FLAGS_FLOATE | FLAGS_UPPER;
        break;
      case 'g':
        type = MTYPE_DOUBLE;
        flags |= FLAGS_FLOATG;
        break;
      case 'G':
        type = MTYPE_DOUBLE;
        flags |= FLAGS_FLOATG | FLAGS_UPPER;
        break;
      default:
        /* invalid instruction, disregard and continue */
        continue;
      } /* switch */

      if(flags & FLAGS_WIDTHPARAM) {
        if(width < 0)
          width = param_num++;
        else {
          /* if this identifies a parameter already used, this is illegal */
          if(is_arg_used(usedinput, width))
            return PFMT_WIDTHARG;
        }
        if(width >= MAX_PARAMETERS)
          return PFMT_MANYARGS;
        if(width >= max_param)
          max_param = width;

        in[width].type = MTYPE_WIDTH;
        /* mark as used */
        mark_arg_used(usedinput, width);
      }

      if(flags & FLAGS_PRECPARAM) {
        if(precision < 0)
          precision = param_num++;
        else {
          /* if this identifies a parameter already used, this is illegal */
          if(is_arg_used(usedinput, precision))
            return PFMT_PRECARG;
        }
        if(precision >= MAX_PARAMETERS)
          return PFMT_MANYARGS;
        if(precision >= max_param)
          max_param = precision;

        in[precision].type = MTYPE_PRECISION;
        mark_arg_used(usedinput, precision);
      }

      /* Handle the specifier */
      if(param < 0)
        param = param_num++;
      if(param >= MAX_PARAMETERS)
        return PFMT_MANYARGS;
      if(param >= max_param)
        max_param = param;

      iptr = &in[param];
      iptr->type = type;

      /* mark this input as used */
      mark_arg_used(usedinput, param);

      fmt++;
      optr = &out[ocount++];
      if(ocount > MAX_SEGMENTS)
        return PFMT_MANYSEGS;
      optr->input = (unsigned int)param;
      optr->flags = flags;
      optr->width = width;
      optr->precision = precision;
      optr->start = start;
      optr->outlen = outlen;
      start = fmt;
    }
    else
      fmt++;
  }

  /* is there a trailing piece */
  outlen = (size_t)(fmt - start);
  if(outlen) {
    optr = &out[ocount++];
    if(ocount > MAX_SEGMENTS)
      return PFMT_MANYSEGS;
    optr->input = 0;
    optr->flags = FLAGS_SUBSTR;
    optr->start = start;
    optr->outlen = outlen;
  }

  /* Read the arg list parameters into our data list */
  for(i = 0; i < max_param + 1; i++) {
    struct va_input *iptr = &in[i];
    if(!is_arg_used(usedinput, i))
      /* bad input */
      return PFMT_INPUTGAP;

    /* based on the type, read the correct argument */
    switch(iptr->type) {
    case MTYPE_STRING:
      iptr->val.str = va_arg(arglist, const char *);
      break;

    case MTYPE_INTPTR:
    case MTYPE_PTR:
      iptr->val.ptr = va_arg(arglist, void *);
      break;

    case MTYPE_LONGLONGU:
      iptr->val.numu = va_arg(arglist, uint64_t);
      break;

    case MTYPE_LONGLONG:
      iptr->val.nums = va_arg(arglist, int64_t);
      break;

    case MTYPE_LONGU:
      iptr->val.numu = va_arg(arglist, unsigned long);
      break;

    case MTYPE_LONG:
      iptr->val.nums = va_arg(arglist, long);
      break;

    case MTYPE_INTU:
      iptr->val.numu = va_arg(arglist, unsigned int);
      break;

    case MTYPE_INT:
    case MTYPE_WIDTH:
    case MTYPE_PRECISION:
      iptr->val.nums = va_arg(arglist, int);
      break;

    case MTYPE_DOUBLE:
      iptr->val.dnum = va_arg(arglist, double);
      break;

    default:
      DEBUGASSERT(NULL); /* unexpected */
      break;
    }
  }
  *ipieces = max_param + 1;
  *opieces = ocount;

  return PFMT_OK;
}

struct mproperty {
  int width;            /* Width of a field.  */
  int prec;             /* Precision of a field.  */
  unsigned int flags;
};

static bool out_double(void *userp,
                       int (*stream)(unsigned char, void *),
                       struct mproperty *p,
                       double dnum,
                       char *work, int *donep)
{
  char formatbuf[32] = "%";
  char *fptr = &formatbuf[1];
  size_t left = sizeof(formatbuf) - strlen(formatbuf);
  int flags = p->flags;
  int width = p->width;
  int prec = p->prec;

  if(flags & FLAGS_LEFT)
    *fptr++ = '-';
  if(flags & FLAGS_SHOWSIGN)
    *fptr++ = '+';
  if(flags & FLAGS_SPACE)
    *fptr++ = ' ';
  if(flags & FLAGS_ALT)
    *fptr++ = '#';

  *fptr = 0;

  if(width >= 0) {
    size_t dlen;
    if(width >= BUFFSIZE)
      width = BUFFSIZE - 1;
    /* RECURSIVE USAGE */
    dlen = (size_t)curl_msnprintf(fptr, left, "%d", width);
    fptr += dlen;
    left -= dlen;
  }
  if(prec >= 0) {
    /* for each digit in the integer part, we can have one less
       precision */
    int maxprec = BUFFSIZE - 1;
    double val = dnum;
    int len;
    if(prec > maxprec)
      prec = maxprec - 1;
    if(width > 0 && prec <= width)
      maxprec -= width;
    while(val >= 10.0) {
      val /= 10;
      maxprec--;
    }

    if(prec > maxprec)
      prec = maxprec - 1;
    if(prec < 0)
      prec = 0;
    /* RECURSIVE USAGE */
    len = curl_msnprintf(fptr, left, ".%d", prec);
    fptr += len;
  }
  if(flags & FLAGS_LONG)
    *fptr++ = 'l';

  if(flags & FLAGS_FLOATE)
    *fptr++ = (char)((flags & FLAGS_UPPER) ? 'E' : 'e');
  else if(flags & FLAGS_FLOATG)
    *fptr++ = (char)((flags & FLAGS_UPPER) ? 'G' : 'g');
  else
    *fptr++ = 'f';

  *fptr = 0; /* and a final null-termination */

  /* NOTE NOTE NOTE!! Not all sprintf implementations return number of
     output characters */
#ifdef HAVE_SNPRINTF
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
#endif
  (snprintf)(work, BUFFSIZE, formatbuf, dnum);
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif
#ifdef _WIN32
  /* Old versions of the Windows CRT do not terminate the snprintf output
     buffer if it reaches the max size so we do that here. */
  work[BUFFSIZE - 1] = 0;
#endif
#else
  /* float and double outputs do not work without snprintf support */
  work[0] = 0;
#endif
  DEBUGASSERT(strlen(work) < BUFFSIZE);
  while(*work) {
    if(stream(*work++, userp))
      return TRUE;
    (*donep)++;
  }
  return 0;
}

static bool out_number(void *userp,
                       int (*stream)(unsigned char, void *),
                       struct mproperty *p,
                       uint64_t num,
                       int64_t nums,
                       char *work, int *donep)
{
  const unsigned char *digits = tr_ldigits;
  int flags = p->flags;
  int width = p->width;
  int prec = p->prec;
  bool is_alt = flags & FLAGS_ALT;
  bool is_neg = FALSE;
  int base = 10;

  /* 'workend' points to the final buffer byte position, but with an extra
     byte as margin to avoid the (FALSE?) warning Coverity gives us
     otherwise */
  char *workend = &work[BUFFSIZE - 2];
  char *w;

  if(flags & FLAGS_CHAR) {
    /* Character.  */
    if(!(flags & FLAGS_LEFT))
      while(--width > 0)
        OUTCHAR(' ');
    OUTCHAR((char)num);
    if(flags & FLAGS_LEFT)
      while(--width > 0)
        OUTCHAR(' ');
    return FALSE;
  }
  if(flags & FLAGS_OCTAL)
    /* Octal unsigned integer */
    base = 8;

  else if(flags & FLAGS_HEX) {
    /* Hexadecimal unsigned integer */
    digits = (flags & FLAGS_UPPER) ? tr_udigits : tr_ldigits;
    base = 16;
  }
  else if(flags & FLAGS_UNSIGNED)
    /* Decimal unsigned integer */
    ;

  else {
    /* Decimal integer.  */
    is_neg = (nums < 0);
    if(is_neg) {
      /* signed_num might fail to hold absolute negative minimum by 1 */
      int64_t signed_num; /* Used to convert negative in positive.  */
      signed_num = nums + (int64_t)1;
      signed_num = -signed_num;
      num = (uint64_t)signed_num;
      num += (uint64_t)1;
    }
  }

  /* Supply a default precision if none was given.  */
  if(prec == -1)
    prec = 1;

  /* Put the number in WORK.  */
  w = workend;
  DEBUGASSERT(base <= 16);
  switch(base) {
  case 10:
    while(num > 0) {
      *w-- = (char)('0' + (num % 10));
      num /= 10;
    }
    break;
  default:
    while(num > 0) {
      *w-- = digits[num % base];
      num /= base;
    }
    break;
  }
  width -= (int)(workend - w);
  prec -= (int)(workend - w);

  if(is_alt && base == 8 && prec <= 0) {
    *w-- = '0';
    --width;
  }

  if(prec > 0) {
    width -= prec;
    while(prec-- > 0 && w >= work)
      *w-- = '0';
  }

  if(is_alt && base == 16)
    width -= 2;

  if(is_neg || (flags & FLAGS_SHOWSIGN) || (flags & FLAGS_SPACE))
    --width;

  if(!(flags & FLAGS_LEFT) && !(flags & FLAGS_PAD_NIL))
    while(width-- > 0)
      OUTCHAR(' ');

  if(is_neg)
    OUTCHAR('-');
  else if(flags & FLAGS_SHOWSIGN)
    OUTCHAR('+');
  else if(flags & FLAGS_SPACE)
    OUTCHAR(' ');

  if(is_alt && base == 16) {
    OUTCHAR('0');
    if(flags & FLAGS_UPPER)
      OUTCHAR('X');
    else
      OUTCHAR('x');
  }

  if(!(flags & FLAGS_LEFT) && (flags & FLAGS_PAD_NIL))
    while(width-- > 0)
      OUTCHAR('0');

  /* Write the number.  */
  while(++w <= workend) {
    OUTCHAR(*w);
  }

  if(flags & FLAGS_LEFT)
    while(width-- > 0)
      OUTCHAR(' ');

  return FALSE;
}

static const char nilstr[] = "(nil)";

static bool out_string(void *userp,
                       int (*stream)(unsigned char, void *),
                       struct mproperty *p,
                       const char *str,
                       int *donep)
{
  int flags = p->flags;
  int width = p->width;
  int prec = p->prec;
  size_t len;

  if(!str) {
    /* Write null string if there is space.  */
    if(prec == -1 || prec >= (int)sizeof(nilstr) - 1) {
      str = nilstr;
      len = sizeof(nilstr) - 1;
      /* Disable quotes around (nil) */
      flags &= ~(unsigned int)FLAGS_ALT;
    }
    else {
      str = "";
      len = 0;
    }
  }
  else if(prec != -1)
    len = (size_t)prec;
  else if(*str == '\0')
    len = 0;
  else
    len = strlen(str);

  width -= (len > INT_MAX) ? INT_MAX : (int)len;

  if(flags & FLAGS_ALT)
    OUTCHAR('"');

  if(!(flags & FLAGS_LEFT))
    while(width-- > 0)
      OUTCHAR(' ');

  for(; len && *str; len--)
    OUTCHAR(*str++);
  if(flags & FLAGS_LEFT)
    while(width-- > 0)
      OUTCHAR(' ');

  if(flags & FLAGS_ALT)
    OUTCHAR('"');

  return FALSE;
}

static bool out_pointer(void *userp,
                        int (*stream)(unsigned char, void *),
                        struct mproperty *p,
                        const char *ptr,
                        char *work,
                        int *donep)
{
  /* Generic pointer.  */
  if(ptr) {
    size_t num = (size_t)ptr;

    /* If the pointer is not NULL, write it as a %#x spec.  */
    p->flags |= FLAGS_HEX | FLAGS_ALT;
    if(out_number(userp, stream, p, num, 0, work, donep))
      return TRUE;
  }
  else {
    /* Write "(nil)" for a nil pointer.  */
    const char *point;
    int width = p->width;
    int flags = p->flags;

    width -= (int)(sizeof(nilstr) - 1);
    if(flags & FLAGS_LEFT)
      while(width-- > 0)
        OUTCHAR(' ');
    for(point = nilstr; *point; ++point)
      OUTCHAR(*point);
    if(!(flags & FLAGS_LEFT))
      while(width-- > 0)
        OUTCHAR(' ');
  }
  return FALSE;
}

/*
 * formatf() - the general printf function.
 *
 * It calls parsefmt() to parse the format string. It populates two arrays;
 * one that describes the input arguments and one that describes a number of
 * output segments.
 *
 * On success, the input array describes the type of all arguments and their
 * values.
 *
 * The function then iterates over the output segments and outputs them one
 * by one until done. Using the appropriate input arguments (if any).
 *
 * All output is sent to the 'stream()' callback, one byte at a time.
 */

static int formatf(void *userp, /* untouched by format(), just sent to the
                                   stream() function in the second argument */
                   /* function pointer called for each output character */
                   int (*stream)(unsigned char, void *),
                   const char *format, /* %-formatted string */
                   va_list ap_save) /* list of parameters */
{
  int done = 0;   /* number of characters written  */
  int i;
  int ocount = 0; /* number of output segments */
  int icount = 0; /* number of input arguments */

  struct outsegment output[MAX_SEGMENTS];
  struct va_input input[MAX_PARAMETERS];
  char work[BUFFSIZE + 2];

  /* Parse the format string */
  if(parsefmt(format, output, input, &ocount, &icount, ap_save))
    return 0;

  for(i = 0; i < ocount; i++) {
    struct outsegment *optr = &output[i];
    struct va_input *iptr = &input[optr->input];
    struct mproperty p;
    size_t outlen = optr->outlen;

    if(outlen) {
      const char *str = optr->start;
      for(; outlen && *str; outlen--) {
        if(stream(*str++, userp))
          return done;
        done++;
      }
      if(optr->flags & FLAGS_SUBSTR)
        /* this is just a substring */
        continue;
    }

    p.flags = optr->flags;

    /* pick up the specified width */
    if(p.flags & FLAGS_WIDTHPARAM) {
      p.width = (int)input[optr->width].val.nums;
      if(p.width < 0) {
        /* "A negative field width is taken as a '-' flag followed by a
           positive field width." */
        if(p.width == INT_MIN)
          p.width = INT_MAX;
        else
          p.width = -p.width;
        p.flags |= FLAGS_LEFT;
        p.flags &= ~(unsigned int)FLAGS_PAD_NIL;
      }
    }
    else
      p.width = optr->width;

    /* pick up the specified precision */
    if(p.flags & FLAGS_PRECPARAM) {
      p.prec = (int)input[optr->precision].val.nums;
      if(p.prec < 0)
        /* "A negative precision is taken as if the precision were
           omitted." */
        p.prec = -1;
    }
    else if(p.flags & FLAGS_PREC)
      p.prec = optr->precision;
    else
      p.prec = -1;

    switch(iptr->type) {
    case MTYPE_INTU:
    case MTYPE_LONGU:
    case MTYPE_LONGLONGU:
      p.flags |= FLAGS_UNSIGNED;
      if(out_number(userp, stream, &p, iptr->val.numu, 0, work, &done))
        return done;
      break;

    case MTYPE_INT:
    case MTYPE_LONG:
    case MTYPE_LONGLONG:
      if(out_number(userp, stream, &p, iptr->val.numu,
                    iptr->val.nums, work, &done))
        return done;
      break;

    case MTYPE_STRING:
      if(out_string(userp, stream, &p, iptr->val.str, &done))
        return done;
      break;

    case MTYPE_PTR:
      if(out_pointer(userp, stream, &p, iptr->val.ptr, work, &done))
        return done;
      break;

    case MTYPE_DOUBLE:
      if(out_double(userp, stream, &p, iptr->val.dnum, work, &done))
        return done;
      break;

    case MTYPE_INTPTR:
      /* Answer the count of characters written.  */
      if(p.flags & FLAGS_LONGLONG)
        *(int64_t *)iptr->val.ptr = (int64_t)done;
      else
        if(p.flags & FLAGS_LONG)
          *(long *)iptr->val.ptr = (long)done;
      else if(!(p.flags & FLAGS_SHORT))
        *(int *)iptr->val.ptr = done;
      else
        *(short *)iptr->val.ptr = (short)done;
      break;

    default:
      break;
    }
  }
  return done;
}

/* fputc() look-alike */
static int addbyter(unsigned char outc, void *f)
{
  struct nsprintf *infop = f;
  if(infop->length < infop->max) {
    /* only do this if we have not reached max length yet */
    *infop->buffer++ = (char)outc; /* store */
    infop->length++; /* we are now one byte larger */
    return 0;     /* fputc() returns like this on success */
  }
  return 1;
}

int curl_mvsnprintf(char *buffer, size_t maxlength, const char *format,
                    va_list ap_save)
{
  int retcode;
  struct nsprintf info;

  info.buffer = buffer;
  info.length = 0;
  info.max = maxlength;

  retcode = formatf(&info, addbyter, format, ap_save);
  if(info.max) {
    /* we terminate this with a zero byte */
    if(info.max == info.length) {
      /* we are at maximum, scrap the last letter */
      info.buffer[-1] = 0;
      DEBUGASSERT(retcode);
      retcode--; /* do not count the nul byte */
    }
    else
      info.buffer[0] = 0;
  }
  return retcode;
}

int curl_msnprintf(char *buffer, size_t maxlength, const char *format, ...)
{
  int retcode;
  va_list ap_save; /* argument pointer */
  va_start(ap_save, format);
  retcode = curl_mvsnprintf(buffer, maxlength, format, ap_save);
  va_end(ap_save);
  return retcode;
}

/* --------------------------------------------------------------------------
 * Allocating variants (curl_maprintf / curl_mvaprintf). curl backs these with
 * its `dynbuf`; here a small malloc/realloc growable buffer (`tr_growbuf`)
 * provides the same "append one byte at a time, return a heap string the caller
 * frees with curl_free" behavior without the dynbuf dependency.
 * -------------------------------------------------------------------------- */

struct tr_growbuf {
  char *buf;
  size_t len;
  size_t cap;
  int err; /* nonzero once an allocation has failed */
};

/* fputc() look-alike that appends into a tr_growbuf, keeping at least one spare
 * byte so a trailing NUL can always be written after formatting completes. */
static int tr_grow_addbyte(unsigned char outc, void *f)
{
  struct tr_growbuf *g = f;
  if(g->err)
    return 1;
  if(g->len + 2 > g->cap) {
    size_t newcap = g->cap ? g->cap * 2 : 64;
    char *nb;
    while(newcap < g->len + 2)
      newcap *= 2;
    nb = (char *)realloc(g->buf, newcap);
    if(!nb) {
      g->err = 1;
      return 1; /* fail */
    }
    g->buf = nb;
    g->cap = newcap;
  }
  g->buf[g->len++] = (char)outc;
  return 0;
}

char *curl_mvaprintf(const char *format, va_list ap_save)
{
  struct tr_growbuf g;
  g.buf = NULL;
  g.len = 0;
  g.cap = 0;
  g.err = 0;

  (void)formatf(&g, tr_grow_addbyte, format, ap_save);
  if(g.err) {
    free(g.buf);
    return NULL;
  }
  if(g.buf) {
    /* tr_grow_addbyte always keeps room for this terminator */
    g.buf[g.len] = 0;
    return g.buf;
  }
  /* zero bytes produced: return a heap-allocated "" (matches curl's
     strdup("")), so the caller's curl_free contract is uniform */
  {
    char *empty = (char *)malloc(1);
    if(empty)
      empty[0] = 0;
    return empty;
  }
}

char *curl_maprintf(const char *format, ...)
{
  va_list ap_save;
  char *s;
  va_start(ap_save, format);
  s = curl_mvaprintf(format, ap_save);
  va_end(ap_save);
  return s;
}

static int storebuffer(unsigned char outc, void *f)
{
  char **buffer = f;
  **buffer = (char)outc;
  (*buffer)++;
  return 0;
}

int curl_msprintf(char *buffer, const char *format, ...)
{
  va_list ap_save; /* argument pointer */
  int retcode;
  va_start(ap_save, format);
  retcode = formatf(&buffer, storebuffer, format, ap_save);
  va_end(ap_save);
  *buffer = 0; /* we terminate this with a zero byte */
  return retcode;
}

static int fputc_wrapper(unsigned char outc, void *f)
{
  int out = outc;
  FILE *s = f;
  int rc = fputc(out, s);
  return rc == EOF;
}

int curl_mprintf(const char *format, ...)
{
  int retcode;
  va_list ap_save; /* argument pointer */
  va_start(ap_save, format);
  retcode = formatf(stdout, fputc_wrapper, format, ap_save);
  va_end(ap_save);
  return retcode;
}

int curl_mfprintf(FILE *whereto, const char *format, ...)
{
  int retcode;
  va_list ap_save; /* argument pointer */
  va_start(ap_save, format);
  retcode = formatf(whereto, fputc_wrapper, format, ap_save);
  va_end(ap_save);
  return retcode;
}

int curl_mvsprintf(char *buffer, const char *format, va_list ap_save)
{
  int retcode = formatf(&buffer, storebuffer, format, ap_save);
  *buffer = 0; /* we terminate this with a zero byte */
  return retcode;
}

int curl_mvprintf(const char *format, va_list ap_save)
{
  return formatf(stdout, fputc_wrapper, format, ap_save);
}

int curl_mvfprintf(FILE *whereto, const char *format, va_list ap_save)
{
  return formatf(whereto, fputc_wrapper, format, ap_save);
}
