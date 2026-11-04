import { describe, expect, it } from "vitest";
import { argsFromValues, fieldsFromSchema, missing } from "../features/palette/SchemaForm";

// As `beezip schema stream.compress` prints it (schemars 1.x).
const streamCompress = {
  $defs: {
    CodecName: {
      description: "A single-stream codec.",
      enum: ["gzip", "zlib", "deflate", "bzip2", "xz", "lzma", "lzip", "zstd", "lz4", "brotli", "snappy"],
      type: "string",
    },
  },
  additionalProperties: false,
  properties: {
    codec: { anyOf: [{ $ref: "#/$defs/CodecName" }, { type: "null" }], description: "The codec [default: from config, zstd]." },
    input: { description: "The file to compress.", type: "string" },
    level: { description: "The compression level.", type: ["integer", "null"] },
    output: { description: "Where to write.", type: ["string", "null"] },
    overwrite: { description: "Replace the output if it exists.", type: ["boolean", "null"] },
    threads: { description: "Compression threads.", minimum: 0, type: ["integer", "null"] },
  },
  required: ["input"],
  type: "object",
};

// The shapes the other commands add: a secret, a documented enum, a list, a number-or-string.
const others = {
  $defs: {
    Secret: { description: "A password.", type: "string" },
    TextEncoding: {
      oneOf: [
        { enum: ["hex", "base64"], type: "string" },
        { const: "text", description: "UTF-8.", type: "string" },
      ],
    },
    ByteSize: { anyOf: [{ minimum: 0, type: "integer" }, { type: "string" }] },
  },
  properties: {
    password: { anyOf: [{ $ref: "#/$defs/Secret" }, { type: "null" }] },
    encoding: { anyOf: [{ $ref: "#/$defs/TextEncoding" }, { type: "null" }], description: "How to return the data." },
    glob: { items: { type: "string" }, type: ["array", "null"] },
    volume_size: { anyOf: [{ $ref: "#/$defs/ByteSize" }, { type: "null" }] },
  },
  type: "object",
};

describe("the schema form", () => {
  it("turns a schema into fields", () => {
    const fields = fieldsFromSchema(streamCompress);
    expect(fields.map((f) => [f.name, f.kind, f.required])).toEqual([
      ["codec", "enum", false],
      ["input", "string", true],
      ["level", "integer", false],
      ["output", "string", false],
      ["overwrite", "boolean", false],
      ["threads", "integer", false],
    ]);
    const codec = fields[0];
    expect(codec.kind === "enum" && codec.options).toContain("zstd");
    expect(codec.description).toBe("The codec [default: from config, zstd].");
    expect(fields[5]).toMatchObject({ min: 0 });

    expect(fieldsFromSchema(others).map((f) => [f.name, f.kind])).toEqual([
      ["password", "secret"],
      ["encoding", "enum"],
      ["glob", "list"],
      ["volume_size", "string"],
    ]);
    const encoding = fieldsFromSchema(others)[1];
    expect(encoding.kind === "enum" && encoding.options).toEqual(["hex", "base64", "text"]);
  });

  it("turns the values into arguments, leaving out empty ones", () => {
    const fields = fieldsFromSchema(streamCompress);
    expect(missing(fields, {})).toEqual(["input"]);
    const args = argsFromValues(fields, {
      input: String.raw`C:\a b\notes.txt`,
      codec: "zstd",
      level: "19",
      output: "  ",
      overwrite: true,
      threads: "",
    });
    expect(args).toEqual({ input: String.raw`C:\a b\notes.txt`, codec: "zstd", level: 19, overwrite: true });
    expect(missing(fields, { input: "x" })).toEqual([]);

    const more = argsFromValues(fieldsFromSchema(others), { glob: "*.txt\n\n docs/** ", volume_size: "100m", password: "p" });
    expect(more).toEqual({ glob: ["*.txt", "docs/**"], volume_size: "100m", password: "p" });
  });
});
