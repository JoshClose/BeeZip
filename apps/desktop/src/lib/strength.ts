// How hard a typed password is to guess, and passphrases to suggest (docs/M14.md §5, decision
// 13). BeeZip's own estimate, not zxcvbn's: a password is cut into pieces (words from the EFF
// list, common passwords, keyboard runs and sequences, repeats, years and single characters),
// each costing the guesses an attacker who knows such patterns would need. It warns under
// about 50 bits, four random words; it never refuses.
import { useEffect, useState } from "react";

/** Under this many bits a password gets a warning: about four random words from the EFF list. */
export const WEAK_BITS = 50;

/** Words in a suggested passphrase: six from the EFF list are about 77 bits. */
export const SUGGESTED_WORDS = 6;

/** The EFF large wordlist: `11111\tabacus` lines, 7,776 of them. */
export function parseWordlist(text: string): string[] {
  const words: string[] = [];
  for (const line of text.split(/\r?\n/)) {
    const word = line.split("\t")[1]?.trim();
    if (word) words.push(word);
  }
  return words;
}

let wordlist: Promise<string[]> | undefined;

/** The EFF list, loaded once when first wanted: it stays out of the start-up bundle. */
export function loadWordlist(): Promise<string[]> {
  wordlist ??= import("./eff_large_wordlist.txt?raw").then((m) => parseWordlist(m.default));
  return wordlist;
}

/** The wordlist, once it has loaded. */
export function useWordlist(): string[] | undefined {
  const [words, setWords] = useState<string[]>();
  useEffect(() => {
    let live = true;
    loadWordlist().then(
      (w) => live && setWords(w),
      () => {},
    );
    return () => {
      live = false;
    };
  }, []);
  return words;
}

/** A uniform whole number below `n`, from the system's random source, without modulo bias. */
export function randomBelow(n: number): number {
  const limit = Math.floor(0x1_0000_0000 / n) * n;
  const buf = new Uint32Array(1);
  for (;;) {
    crypto.getRandomValues(buf);
    if (buf[0] < limit) return buf[0] % n;
  }
}

/** Six words from the list, joined by hyphens: "Suggest one". */
export function suggestPassphrase(words: string[], random: (n: number) => number = randomBelow, count = SUGGESTED_WORDS): string {
  if (words.length < 2) throw new Error("the wordlist hasn't loaded");
  return Array.from({ length: count }, () => words[random(words.length)]).join("-");
}

/** Passwords people pick most often, and the words their variants are built on. Matching one
 * costs an attacker almost nothing, so each counts as a few bits. */
const COMMON = [
  "password", "passw0rd", "qwerty", "letmein", "welcome", "admin", "administrator", "iloveyou", "monkey", "dragon",
  "football", "baseball", "soccer", "hockey", "sunshine", "princess", "master", "shadow", "superman", "batman",
  "trustno1", "secret", "login", "starwars", "whatever", "freedom", "charlie", "michael", "jessica", "ashley",
  "hello", "hunter", "ranger", "buster", "thomas", "jordan", "harley", "robert", "matthew", "daniel", "andrew",
  "summer", "winter", "spring", "autumn", "monday", "friday", "january", "december", "love", "lovely", "angel",
  "flower", "cookie", "cheese", "pepper", "ginger", "orange", "banana", "computer", "internet", "google", "apple",
  "samsung", "microsoft", "windows", "beezip", "changeme", "default", "guest", "test", "temp", "pass", "abc",
  "qazwsx", "zaq12wsx", "killer", "pokemon", "minecraft", "naruto", "liverpool", "chelsea", "arsenal", "family",
  "jesus", "blessed", "money", "secure", "private", "access", "mustang", "corvette", "ferrari", "tigger", "daisy",
];
const COMMON_SET = new Set(COMMON);
/** The bits a common password or base word costs: a list of about a thousand, as attackers use. */
const COMMON_BITS = 10;

/** Keyboard rows and sequences: three or more neighbours in one is a run. */
const RUNS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "qwertzuiop", "azertyuiop", "1234567890", "abcdefghijklmnopqrstuvwxyz", "1qaz2wsx3edc4rfv5tgb6yhn7ujm"];
/** A run costs this, whatever its length: where it starts, which way it goes, how long. */
const RUN_BITS = 7;

/** What leetspeak replaces, put back, so `p@ssw0rd` is `password`. */
const LEET: Record<string, string> = { "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", $: "s", "!": "i", "|": "l", "8": "b" };

function unleet(s: string): string {
  return [...s].map((c) => LEET[c] ?? c).join("");
}

function runLength(s: string, at: number): number {
  let best = 0;
  for (const row of RUNS) {
    for (const r of [row, [...row].reverse().join("")]) {
      let len = 0;
      let pos = r.indexOf(s[at]);
      while (pos >= 0 && at + len < s.length && r[pos + len] === s[at + len]) len++;
      if (len > best) best = len;
    }
  }
  return best >= 3 ? best : 0;
}

function repeatLength(s: string, at: number): number {
  let len = 1;
  while (at + len < s.length && s[at + len] === s[at]) len++;
  return len >= 3 ? len : 0;
}

/** The longest word from `words` or the common list starting at `at`, at least four letters. */
function wordAt(lower: string, at: number, words: Set<string>): { len: number; bits: number } | undefined {
  for (let len = Math.min(14, lower.length - at); len >= 4; len--) {
    const piece = lower.slice(at, at + len);
    const plain = unleet(piece);
    if (COMMON_SET.has(piece) || COMMON_SET.has(plain)) return { len, bits: COMMON_BITS };
    if (words.has(piece) || words.has(plain)) return { len, bits: Math.log2(Math.max(words.size, 2)) };
  }
  return undefined;
}

function poolSize(password: string): number {
  let pool = 0;
  if (/[a-z]/.test(password)) pool += 26;
  if (/[A-Z]/.test(password)) pool += 26;
  if (/[0-9]/.test(password)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(password)) pool += /[^\x20-\x7e]/.test(password) ? 100 : 33;
  return Math.max(pool, 10);
}

export type Strength = {
  /** About how many guesses it would take, as a power of two. */
  bits: number;
  /** Under about 50 bits: BeeZip warns, and leaves the choice to the person. */
  weak: boolean;
  /** One line for under the field. */
  line: string;
};

/** BeeZip's estimate of a password's guesses (docs/M14.md §5). `words` is the EFF list. */
export function estimate(password: string, words: Set<string> = new Set()): Strength {
  const text = password.normalize("NFC");
  if (text.length === 0) return { bits: 0, weak: true, line: "" };
  const lower = text.toLowerCase();
  const charBits = Math.log2(poolSize(text));
  let bits = 0;
  let pieces = 0;
  let at = 0;
  // A separator used again (the hyphens between words) costs almost nothing the second time.
  const separators = new Set<string>();
  while (at < lower.length) {
    const word = wordAt(lower, at, words);
    const run = runLength(lower, at);
    const repeat = repeatLength(lower, at);
    const year = /^(19|20)\d\d/.test(lower.slice(at)) ? 4 : 0;
    // The piece that covers the most characters, so `password` is one word and not eight letters.
    const best = Math.max(word?.len ?? 0, run, repeat, year);
    if (best === 0) {
      const c = lower[at];
      const separator = !/[\p{L}\p{N}]/u.test(c);
      bits += separator && separators.has(c) ? 1 : charBits;
      if (separator) separators.add(c);
      at += 1;
    } else {
      if (best === (word?.len ?? 0)) bits += word!.bits;
      else if (best === run) bits += RUN_BITS;
      else if (best === repeat) bits += 4;
      else bits += 7; // a year: about 130 likely ones
      // Capitals somewhere in the piece cost a guess or two more.
      if (text.slice(at, at + best) !== lower.slice(at, at + best)) bits += 1;
      at += best;
    }
    pieces++;
  }
  // Pieces are guessed in order: a few bits for how they were put together.
  bits += Math.log2(pieces);
  const rounded = Math.round(bits);
  const weak = bits < WEAK_BITS;
  const verdict = bits < 28 ? "very weak, guessed in moments." : weak ? "weak. Four random words or more are safer." : bits < 70 ? "good." : "strong.";
  return { bits, weak, line: `About ${rounded} bits: ${verdict}` };
}
