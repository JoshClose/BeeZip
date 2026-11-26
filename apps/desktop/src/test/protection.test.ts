import { describe, expect, it, vi } from "vitest";
import { outputSummary } from "../features/jobs/JobsPanel";
import type { KeyInfo, WayIn } from "../gen/commands";
import { applyEvent, newJob, withoutSecrets } from "../lib/jobs";
import {
  addWaysArgs,
  checkProtection,
  encryptedBhive,
  formatRecoveryKey,
  NO_PROTECTION,
  parseRecipient,
  protectionArgs,
  type ProtectionForm,
  publicKeyKind,
  recipientArgs,
  recoveryKeyProblem,
  slotPostQuantum,
} from "../lib/protection";
import { estimate, loadWordlist, parseWordlist, randomBelow, suggestPassphrase, WEAK_BITS } from "../lib/strength";

// age's own example keys (age-encryption.org/v1): the classic recipient, and a post-quantum one.
const CLASSIC = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p";
const PQ = `age1pq1${"q".repeat(1900)}`;

const key = (name: string, patch: Partial<KeyInfo> = {}): KeyInfo => ({ name, kind: "post-quantum", public: `${PQ}${name}`, fingerprint: "AAAA-BBBB-CCCC-DDDD", own: false, created: 0, ...patch });
const form = (patch: Partial<ProtectionForm>): ProtectionForm => ({ ...NO_PROTECTION, ...patch });

describe("the strength estimate (docs/M14.md §5)", () => {
  it("rates common passwords, runs and repeats as very weak", () => {
    for (const p of ["summer2026", "Summer2026!", "P@ssw0rd!", "qwertyuiop", "aaaaaaaaaaaa", "123456789", "Password1", "letmein2024"]) {
      const s = estimate(p);
      expect(s.bits, p).toBeLessThan(28);
      expect(s.weak).toBe(true);
      expect(s.line).toMatch(/very weak/);
    }
  });

  it("warns under about 50 bits and not above", () => {
    // Seven random characters: weak, not very weak.
    const seven = estimate("k9#mQ2x");
    expect(seven.weak).toBe(true);
    expect(seven.line).toMatch(/: weak\. Four random words/);
    const strong = estimate("Xk9#mQ2$vL7&pR4!");
    expect(strong.bits).toBeGreaterThan(90);
    expect(strong.weak).toBe(false);
    expect(strong.line).toMatch(/^About \d+ bits: strong\.$/);
    expect(estimate("").bits).toBe(0);
  });

  it("counts words from the EFF list as words, and the hyphens between them as little", async () => {
    const words = await loadWordlist();
    const set = new Set(words);
    const six = estimate("abacus-zoology-hamper-cobalt-mustang-quiver", set);
    expect(six.bits).toBeGreaterThan(77);
    expect(six.bits).toBeLessThan(95);
    const two = estimate("abacus-zoology", set);
    expect(two.weak).toBe(true);
    expect(two.bits).toBeGreaterThanOrEqual(26);
    // Normalised to NFC first: the same password typed on macOS and Windows rates the same.
    expect(estimate("caf\u0065\u0301-x").bits).toBe(estimate("caf\u00e9-x").bits);
    expect(WEAK_BITS).toBe(50);
  });

  it("loads the EFF large wordlist: 7,776 words", async () => {
    const words = await loadWordlist();
    expect(words).toHaveLength(7776);
    expect(words[0]).toBe("abacus");
    expect(words[7775]).toBe("zoom");
    expect(parseWordlist("11111\tabacus\r\n11112\tabdomen\n\n")).toEqual(["abacus", "abdomen"]);
  });

  it("suggests six words joined by hyphens, leaving out the list's own hyphenated words", async () => {
    expect(suggestPassphrase(["a", "b", "c"], () => 1)).toBe("b-b-b-b-b-b");
    // drop-down, felt-tip, t-shirt and yo-yo would read as two words each.
    expect(suggestPassphrase(["drop-down", "a", "yo-yo", "b"], (n) => n - 1)).toBe("b-b-b-b-b-b");
    const words = await loadWordlist();
    expect(words.filter((w) => w.includes("-"))).toEqual(["drop-down", "felt-tip", "t-shirt", "yo-yo"]);
    // Every pick lands on a word with no hyphen, whatever the random source gives.
    const pool = words.filter((w) => !w.includes("-"));
    const seen: number[] = [];
    const phrase = suggestPassphrase(words, (n) => {
      expect(n).toBe(7772);
      seen.push(seen.length === 0 ? 0 : n - 1);
      return seen[seen.length - 1];
    });
    expect(phrase).toBe([pool[0], ...Array(5).fill(pool[7771])].join("-"));
    expect(phrase.split("-")).toHaveLength(6);
    expect(() => suggestPassphrase([])).toThrow();
  });

  it("picks words without bias: values past the last whole multiple are drawn again", () => {
    const n = 7776;
    const limit = Math.floor(0x1_0000_0000 / n) * n;
    const draws = [limit, 0xffff_ffff, limit - 1];
    const spy = vi.spyOn(crypto, "getRandomValues").mockImplementation(<T extends ArrayBufferView | null>(buf: T): T => {
      (buf as unknown as Uint32Array)[0] = draws.shift()!;
      return buf;
    });
    try {
      // The first two would favour the lowest words; the third is used.
      expect(randomBelow(n)).toBe((limit - 1) % n);
      expect(draws).toHaveLength(0);
    } finally {
      spy.mockRestore();
    }
    for (let i = 0; i < 200; i++) {
      const v = randomBelow(n);
      expect(v).toBeGreaterThanOrEqual(0);
      expect(v).toBeLessThan(n);
    }
  });

  it("counts the number row's shifted keys and its zigzag as keyboard runs", () => {
    for (const p of ["1q2w3e4r5t6y", "!@#$%^&*()", "1q2w3e4r"]) expect(estimate(p).weak, p).toBe(true);
  });
});

describe("secrets in the jobs panel (docs/M14.md §8)", () => {
  const KEY = "123456-234567-345678-456789-567890-678901-789012-890123";
  const finished = (command: string, output: unknown) =>
    applyEvent(newJob(1, command, {}, { title: command }, 0), { type: "Finished", output: output as never }, 1).output;

  it("keeps a new recovery key or an exported key out of the job's record", () => {
    const protect = { ways: [{ slot: 0, kind: "recovery-key", machine_bound: false, post_quantum: true }], post_quantum: true, recovery_key: KEY };
    expect(finished("archive.protect", protect)).toEqual({ ways: protect.ways, post_quantum: true });
    expect(finished("archive.create", { path: "a.bhive", recovery_key: KEY })).toEqual({ path: "a.bhive" });
    expect(finished("keys.export", { text: "AGE-SECRET-KEY-1XYZ" })).toEqual({});
    expect(withoutSecrets("archive.test", { entries: 1 })).toEqual({ entries: 1 });
    expect(withoutSecrets("archive.list", null)).toBeNull();
  });

  it("says what protect, sign and keys jobs did without their secrets", () => {
    const ways = [{ slot: 0, kind: "recovery-key", machine_bound: false, post_quantum: true }];
    expect(outputSummary("archive.protect", { ways, post_quantum: true, recovery_key: KEY })).toBe("1 way in, every one post-quantum");
    expect(outputSummary("archive.protection", { encrypted: true, ways: [...ways, ...ways], post_quantum: false })).toBe("2 ways in, some of them classic");
    expect(outputSummary("archive.sign", { signatures: [] })).toBe("No signatures now");
    expect(outputSummary("archive.sign", { signatures: [{}, {}] })).toBe("2 signatures now");
    expect(outputSummary("keys.create", key("Ann"))).toBe("Made Ann (AAAA-BBBB-CCCC-DDDD)");
    expect(outputSummary("keys.import", key("Bob"))).toBe("Added Bob (AAAA-BBBB-CCCC-DDDD)");
    expect(outputSummary("keys.delete", { deleted: "Ann" })).toBe("Deleted Ann");
    expect(outputSummary("keys.export", { text: "AGE-SECRET-KEY-1XYZ" })).toBe("Exported the key");
    expect(outputSummary("keys.list", { keys: [key("Ann")] })).toBe("1 key");
    expect(outputSummary("certificates.list", { certificates: [] })).toBe("0 certificates");
    // Anything else is its JSON, without a secret it may carry.
    expect(outputSummary("archive.unknown", { recovery_key: KEY, ok: true })).toBe(`{"ok":true}`);
  });
});

describe("recipients", () => {
  it("knows public keys, contacts by name or key, and refuses private and signing keys", () => {
    const keys = [key("Ann"), key("Me", { own: true, kind: "classic", public: CLASSIC }), key("Signer", { kind: "signing", public: "bzsig1xyz" })];
    expect(publicKeyKind(PQ)).toBe("post-quantum");
    expect(publicKeyKind(CLASSIC)).toBe("classic");
    expect(publicKeyKind("hello")).toBeUndefined();
    expect(parseRecipient(` ${PQ} `, [])).toEqual({ kind: "key", text: PQ });
    expect(parseRecipient("ann", keys)).toEqual({ kind: "contact", name: "Ann", postQuantum: true, own: false });
    expect(parseRecipient(CLASSIC, keys)).toEqual({ kind: "contact", name: "Me", postQuantum: false, own: true });
    expect(parseRecipient("AGE-SECRET-KEY-1QQQ", keys)).toMatchObject({ error: expect.stringMatching(/private key/) });
    expect(parseRecipient("bzsig1abc", keys)).toMatchObject({ error: expect.stringMatching(/signing key/) });
    // A signing contact's name isn't someone to encrypt to.
    expect(parseRecipient("Signer", keys)).toMatchObject({ error: expect.any(String) });
    expect(parseRecipient("", keys)).toMatchObject({ error: expect.any(String) });
  });

  it("sends keys and names as `to`, thumbprints and files as `to_cert`", () => {
    expect(
      recipientArgs([
        { kind: "key", text: CLASSIC },
        { kind: "contact", name: "Ann", postQuantum: true, own: false },
        { kind: "certificate", thumbprint: "AB12", subject: "CN=Bob" },
        { kind: "certificate-file", path: String.raw`C:\certs\carol.cer` },
      ]),
    ).toEqual({ to: [CLASSIC, "Ann"], to_cert: ["AB12", String.raw`C:\certs\carol.cer`] });
    expect(recipientArgs([])).toEqual({});
  });
});

describe("the protection arguments", () => {
  it("sends only what is set, and the strength only with a password", () => {
    expect(protectionArgs(NO_PROTECTION, "")).toEqual({});
    expect(protectionArgs(form({ strength: "strong" }), "")).toEqual({});
    expect(protectionArgs(form({ strength: "strong", recoveryKey: true, thisPc: true, thisPcPin: "1234", securityKey: true }), "pw")).toEqual({
      strength: "strong",
      recovery_key: true,
      this_pc: true,
      this_pc_pin: "1234",
      security_key: true,
    });
    // This PC and security keys are Windows'.
    expect(protectionArgs(form({ thisPc: true, securityKey: true }), "pw", false)).toEqual({});
  });

  it("adds ways with `archive.protect`'s names", () => {
    expect(addWaysArgs(form({ recoveryKey: true, strength: "strong" }), "pw")).toEqual({ add_password: "pw", recovery_key: true, strength: "strong" });
    expect(addWaysArgs(form({ recipients: [{ kind: "key", text: CLASSIC }] }), "")).toEqual({ to: [CLASSIC] });
  });
});

describe("what the dialogs say about the ways in", () => {
  it("refuses This PC alone, and allows it with a way that leaves the machine (decision 11)", () => {
    expect(checkProtection(form({ thisPc: true }), "").problem).toMatch(/only on this computer/);
    expect(checkProtection(form({ thisPc: true }), "pw").problem).toBeUndefined();
    expect(checkProtection(form({ thisPc: true, recoveryKey: true }), "").problem).toBeUndefined();
    // Off Windows there is no This PC to refuse.
    expect(checkProtection(form({ thisPc: true }), "", false).problem).toBeUndefined();
    // Adding This PC to an archive that already has a portable way in.
    const existing: WayIn[] = [{ slot: 0, kind: "password", machine_bound: false, post_quantum: true }];
    expect(checkProtection(form({ thisPc: true }), "", true, existing).problem).toBeUndefined();
  });

  it("warns when a password is mixed with someone else's key, not your own (decision 12)", () => {
    const mixing = /could also make an archive your password opens/;
    expect(checkProtection(form({ recipients: [{ kind: "key", text: CLASSIC }] }), "pw").warnings.join()).toMatch(mixing);
    expect(checkProtection(form({ recipients: [{ kind: "certificate", thumbprint: "AB", subject: "CN=Bob" }] }), "pw").warnings.join()).toMatch(mixing);
    expect(checkProtection(form({ recipients: [{ kind: "contact", name: "Me", postQuantum: true, own: true }] }), "pw").warnings.join()).not.toMatch(mixing);
    expect(checkProtection(form({ recipients: [{ kind: "key", text: CLASSIC }] }), "").warnings.join()).not.toMatch(mixing);
  });

  it("warns either way round: a password added beside someone else's key already there", () => {
    const mixing = /could also make an archive your password opens/;
    const theirs: WayIn = { slot: 0, kind: "post-quantum-key", recipient: `${PQ}Ann`, machine_bound: false, post_quantum: true };
    const mine: WayIn = { slot: 1, kind: "post-quantum-key", recipient: `${PQ}Me`, machine_bound: false, post_quantum: true };
    const keys = [key("Ann"), key("Me", { own: true })];
    expect(checkProtection(NO_PROTECTION, "pw", true, [theirs], keys).warnings.join()).toMatch(mixing);
    // A key nobody here knows is someone else's too.
    expect(checkProtection(NO_PROTECTION, "pw", true, [theirs], []).warnings.join()).toMatch(mixing);
    // Your own key, This PC and a security key aren't.
    const thisPc: WayIn = { slot: 2, kind: "ec-p256", machine_bound: true, post_quantum: false };
    const securityKey: WayIn = { slot: 3, kind: "security-key", machine_bound: false, post_quantum: true };
    expect(checkProtection(NO_PROTECTION, "pw", true, [mine, thisPc, securityKey], keys).warnings.join()).not.toMatch(mixing);
    // Adding a recovery key beside someone's key mixes nothing.
    expect(checkProtection(form({ recoveryKey: true }), "", true, [theirs], keys).warnings.join()).not.toMatch(mixing);
    // The other way round, as before: someone's key added beside a password already there.
    const password: WayIn = { slot: 4, kind: "password", machine_bound: false, post_quantum: true };
    expect(checkProtection(form({ recipients: [{ kind: "key", text: CLASSIC }] }), "", true, [password], keys).warnings.join()).toMatch(mixing);
  });

  it("says whether it resists quantum computers (decision 9)", () => {
    expect(checkProtection(NO_PROTECTION, "").quantum).toBeUndefined();
    expect(checkProtection(form({ recoveryKey: true, securityKey: true, recipients: [{ kind: "key", text: PQ }] }), "pw")).toMatchObject({
      postQuantum: true,
      quantum: "Resists quantum computers: every way in is post-quantum.",
      ways: 4,
    });
    const classic = checkProtection(form({ thisPc: true, recipients: [{ kind: "certificate", thumbprint: "AB", subject: "CN=Bob" }] }), "pw");
    expect(classic.postQuantum).toBe(false);
    expect(classic.quantum).toBe("Doesn't resist quantum computers: CN=Bob and This PC use classic keys.");
    expect(slotPostQuantum("password")).toBe(true);
    expect(slotPostQuantum("ec-p256")).toBe(false);
  });

  it("knows an encrypted .bhive", () => {
    expect(encryptedBhive({ format: "bhive", encryption: "all" })).toBe(true);
    expect(encryptedBhive({ format: "bhive", encryption: "none" })).toBe(false);
    expect(encryptedBhive({ format: "zip", encryption: "all" })).toBe(false);
    expect(encryptedBhive(undefined)).toBe(false);
  });
});

describe("recovery keys (docs/bhive.md §12.5)", () => {
  const good = ["000011", "000022", "000033", "000044", "000055", "000066", "000077", "720885"].join("-");

  it("groups what's typed into 8 groups of 6", () => {
    expect(formatRecoveryKey("0000110000 22")).toBe("000011-000022");
    expect(formatRecoveryKey(good.replace(/-/g, " "))).toBe(good);
    expect(formatRecoveryKey(`${good}99`)).toBe(good);
  });

  it("finds a typo before anything is tried", () => {
    expect(recoveryKeyProblem(good)).toBeUndefined();
    expect(recoveryKeyProblem(good.replace(/ /g, ""))).toBeUndefined();
    expect(recoveryKeyProblem("123")).toMatch(/48 digits; this has 3/);
    expect(recoveryKeyProblem(good.replace("000033", "000034"))).toBe("Group 3 (000034) has a typo.");
    // A multiple of 11 that is too big for 16 bits.
    expect(recoveryKeyProblem(good.replace("720885", "720896"))).toBe("Group 8 (720896) has a typo.");
  });
});
