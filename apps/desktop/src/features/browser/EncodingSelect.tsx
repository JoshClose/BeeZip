// The name encoding a tab reads its archive's names in (docs/M5.md §8.4), in the info dialog
// and in a dialog of its own from the palette.
import { Button } from "../../components/ui/button";
import { Dialog } from "../../components/ui/dialog";
import { Field, Select } from "../../components/ui/input";
import type { NameEncoding } from "../../gen/commands";
import { type Tab, useArchives } from "../../lib/archives";
import { NAME_ENCODINGS } from "../../lib/encodings";

const DEFAULT = "";

export function EncodingSelect({ tab, id }: { tab: Tab; id: string }) {
  const setEncoding = useArchives((s) => s.setEncoding);
  return (
    <Select
      id={id}
      className="w-80 max-w-full"
      value={tab.encoding ?? DEFAULT}
      onChange={(e) => setEncoding(tab.id, e.target.value === DEFAULT ? undefined : (e.target.value as NameEncoding))}
    >
      <option value={DEFAULT}>As in the settings</option>
      {NAME_ENCODINGS.map((o) => (
        <option key={o.id} value={o.id}>
          {o.label}
        </option>
      ))}
    </Select>
  );
}

export const ENCODING_HINT =
  "For names an archive stores as bytes: zips without the UTF-8 flag, and tars. Choose another if the names look wrong.";

export function EncodingDialog({ tab, onClose }: { tab: Tab; onClose: () => void }) {
  return (
    <Dialog
      open
      onClose={onClose}
      title={`Name encoding for ${tab.name}`}
      className="w-[32rem]"
      footer={
        <Button variant="primary" onClick={onClose}>
          Done
        </Button>
      }
    >
      <Field label="Read the names as" htmlFor="tab-encoding" hint={ENCODING_HINT}>
        <EncodingSelect tab={tab} id="tab-encoding" />
      </Field>
    </Dialog>
  );
}
