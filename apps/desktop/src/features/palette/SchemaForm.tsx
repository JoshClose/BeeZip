// A form built from a command's input schema, for commands without a dialog of their own
// (docs/M3.md §5.3): strings and paths, numbers, booleans, enums and string lists. A new
// command shows up here without UI work.
import { Play } from "lucide-react";
import { useMemo, useState } from "react";
import { Button } from "../../components/ui/button";
import { Checkbox } from "../../components/ui/checkbox";
import { Dialog } from "../../components/ui/dialog";
import { Field, Input, Select, Textarea } from "../../components/ui/input";
import type { CommandName } from "../../gen/commands";
import type { GuiCommand, JsonSchema } from "../../lib/engine";
import { useJobs } from "../../lib/jobs";
import { toastError } from "../../lib/toasts";
import { CopyAsCli } from "../cli/CopyAsCli";

export type FormField =
  | { name: string; kind: "string" | "secret"; required: boolean; description: string }
  | { name: string; kind: "integer" | "number"; required: boolean; description: string; min?: number }
  | { name: string; kind: "boolean"; required: boolean; description: string }
  | { name: string; kind: "enum"; required: boolean; description: string; options: string[] }
  | { name: string; kind: "list"; required: boolean; description: string };

type Schema = JsonSchema & {
  $ref?: string;
  anyOf?: Schema[];
  oneOf?: Schema[];
  type?: string | string[];
  enum?: unknown[];
  const?: unknown;
  items?: Schema;
  minimum?: number;
  description?: string;
};

function resolve(s: Schema, defs: Record<string, Schema>): Schema {
  if (s.$ref) {
    const name = s.$ref.split("/").pop() ?? "";
    return { ...resolve(defs[name] ?? {}, defs), description: s.description ?? defs[name]?.description };
  }
  // `Option<T>` is `anyOf: [T, null]`.
  const alts = s.anyOf?.filter((a) => a.type !== "null");
  if (alts && alts.length === 1) return { ...resolve(alts[0], defs), description: s.description };
  return s;
}

function enumValues(s: Schema): string[] | undefined {
  if (Array.isArray(s.enum)) return s.enum.map(String);
  if (s.oneOf) {
    const values = s.oneOf.flatMap((o) => (Array.isArray(o.enum) ? o.enum.map(String) : o.const !== undefined ? [String(o.const)] : []));
    if (values.length > 0) return values;
  }
  return undefined;
}

/** The fields of a command's form, in schema order. */
export function fieldsFromSchema(schema: JsonSchema): FormField[] {
  const props = (schema.properties ?? {}) as Record<string, Schema>;
  const defs = (schema.$defs ?? {}) as Record<string, Schema>;
  const required = new Set((schema.required as string[] | undefined) ?? []);
  const fields: FormField[] = [];
  for (const [name, raw] of Object.entries(props)) {
    const isSecret = raw.$ref?.endsWith("/Secret") || raw.anyOf?.some((a) => a.$ref?.endsWith("/Secret"));
    const s = resolve(raw, defs);
    const base = { name, required: required.has(name), description: (raw.description ?? s.description ?? "").split("\n")[0] };
    const types = Array.isArray(s.type) ? s.type.filter((t) => t !== "null") : s.type ? [s.type] : [];
    const options = enumValues(s);
    if (isSecret) fields.push({ ...base, kind: "secret" });
    else if (options) fields.push({ ...base, kind: "enum", options });
    else if (types[0] === "boolean") fields.push({ ...base, kind: "boolean" });
    else if (types[0] === "integer" || types[0] === "number") fields.push({ ...base, kind: types[0], min: s.minimum });
    else if (types[0] === "array") fields.push({ ...base, kind: "list" });
    // Strings, paths, and unions such as `number | string` (`ByteSize`) take text.
    else fields.push({ ...base, kind: "string" });
  }
  return fields;
}

export type FormValues = Record<string, string | boolean>;

/** The arguments the form's values make; empty optional fields are left out. */
export function argsFromValues(fields: FormField[], values: FormValues): Record<string, unknown> {
  const args: Record<string, unknown> = {};
  for (const f of fields) {
    const v = values[f.name];
    if (f.kind === "boolean") {
      if (v === true) args[f.name] = true;
      continue;
    }
    if (typeof v !== "string" || v.trim() === "") continue;
    switch (f.kind) {
      case "integer":
      case "number": {
        const n = Number(v);
        if (!Number.isNaN(n)) args[f.name] = n;
        break;
      }
      case "list":
        args[f.name] = v
          .split(/\r?\n/)
          .map((s) => s.trim())
          .filter(Boolean);
        break;
      default:
        // A bare number is a number for `number | string` fields like `ByteSize`.
        args[f.name] = v;
    }
  }
  return args;
}

/** Required fields that are still empty. */
export function missing(fields: FormField[], values: FormValues): string[] {
  return fields.filter((f) => f.required && f.kind !== "boolean" && !String(values[f.name] ?? "").trim()).map((f) => f.name);
}

export function FormDialog({ command, defaults, onClose }: { command: GuiCommand; defaults: FormValues; onClose: () => void }) {
  const track = useJobs((s) => s.track);
  const fields = useMemo(() => fieldsFromSchema(command.input_schema), [command]);
  const [values, setValues] = useState<FormValues>(() => {
    const v: FormValues = {};
    for (const f of fields) if (defaults[f.name] !== undefined) v[f.name] = defaults[f.name];
    return v;
  });
  const args = argsFromValues(fields, values);
  const blank = missing(fields, values);
  const set = (name: string, v: string | boolean) => setValues((s) => ({ ...s, [name]: v }));

  const runIt = () => {
    track(command.name as CommandName, args as never, { title: command.name }).catch((e) => toastError(e, command.name));
    onClose();
  };

  return (
    <Dialog
      open
      onClose={onClose}
      title={command.name}
      description={command.description.split("\n\n")[0]}
      className="w-[40rem]"
      footer={
        <>
          {command.cli !== null && <CopyAsCli command={command.name} args={args} disabled={blank.length > 0} />}
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" onClick={runIt} disabled={blank.length > 0}>
            <Play /> Run
          </Button>
        </>
      }
    >
      <div className="flex flex-col gap-3 pb-2">
        {fields.length === 0 && <p className="text-muted">This command takes no arguments.</p>}
        {fields.map((f) => {
          const id = `field-${f.name}`;
          const label = f.required ? `${f.name} *` : f.name;
          const value = values[f.name];
          if (f.kind === "boolean")
            return (
              <Field key={f.name} label={f.name} hint={f.description}>
                <div className="pt-1">
                  <Checkbox checked={value === true} onChange={(c) => set(f.name, c)} label="Yes" />
                </div>
              </Field>
            );
          return (
            <Field key={f.name} label={label} htmlFor={id} hint={f.description}>
              {f.kind === "enum" ? (
                <Select id={id} value={String(value ?? "")} onChange={(e) => set(f.name, e.target.value)} className="w-56">
                  <option value="">{f.required ? "Choose…" : "Default"}</option>
                  {f.options.map((o) => (
                    <option key={o} value={o}>
                      {o}
                    </option>
                  ))}
                </Select>
              ) : f.kind === "list" ? (
                <Textarea id={id} rows={2} value={String(value ?? "")} onChange={(e) => set(f.name, e.target.value)} placeholder="One per line" />
              ) : (
                <Input
                  id={id}
                  type={f.kind === "secret" ? "password" : f.kind === "string" ? "text" : "number"}
                  min={"min" in f ? f.min : undefined}
                  value={String(value ?? "")}
                  onChange={(e) => set(f.name, e.target.value)}
                />
              )}
            </Field>
          );
        })}
      </div>
    </Dialog>
  );
}
